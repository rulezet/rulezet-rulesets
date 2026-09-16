import "pe"
rule INDICATOR_RMM_DWAgent_CERT {
    meta:
        author = "ditekSHen"
        description = "Detects DWAgent by certificate. Review RMM Inventory"
        thumbprint = "4a13f46def2c9427898a46a88a6a2122ed106b37"
        reference1 = "https://github.com/ditekshen/detection/blob/master/RMM_Inventory.csv"
        reference2 = "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-025a"
        reference3 = "https://www.cisa.gov/sites/default/files/2023-06/Guide%20to%20Securing%20Remote%20Access%20Software_clean%20Final_508c.pdf"
        reference4 = "https://www.cisa.gov/sites/default/files/2023-08/JCDC_RMM_Cyber_Defense_Plan_TLP_CLEAR_508c_1.pdf"
    condition:
        uint16(0) == 0x5a4d and
        for any i in (0..pe.number_of_signatures): (
            pe.signatures[i].subject contains "DWSNET srl" and
            pe.signatures[i].issuer contains "Sectigo Public Code Signing CA R36" and
            pe.signatures[i].serial == "00:af:bd:d3:be:b2:4e:1d:e7:37:82:e9:f8:34:7c:f1:53"
        )
}