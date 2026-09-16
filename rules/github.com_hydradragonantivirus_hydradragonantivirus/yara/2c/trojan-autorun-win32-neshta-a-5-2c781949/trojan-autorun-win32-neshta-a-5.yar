rule Trojan_Autorun_Win32_Neshta_A_5 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Win32.Neshta.A_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e61ec4fd96679b695b8b9d3e07ebe7f75c23c07c6db5aa758454e4e026be9487"

  strings:
    $s1  = "pany for any reason, please contact Mead & Company by email at scriptx@meadroid.com" fullword ascii
    $s2  = "* Applications Software. You may install and use MULTIPLE copies of the SOFTWARE PRODUCT on multiple computers, and copy the \"S" ascii
    $s3  = "If you acquired this product in the United Kingdom, this PLA is governed by British law. If this product was acquired outside th" ascii
    $s4  = "* Mead & Company reserves all rights not expressly granted to you." fullword ascii
    $s5  = "ation. Commercial organisations wishing to license ScriptX 5.0 should contact sxlicense@meadroid.com for further information." fullword ascii
    $s6  = "* Support Services. Mead & Company may provide you with support services related to the SOFTWARE PRODUCT (\"Support Services\") " ascii
    $s7  = "* Termination. Without prejudice to any other rights, Mead & Company may terminate this PLA if you fail to comply with the terms" ascii
    $s8  = "* Termination. Without prejudice to any other rights, Mead & Company may terminate this PLA if you fail to comply with the terms" ascii
    $s9  = "* Support Services. Mead & Company may provide you with support services related to the SOFTWARE PRODUCT (\"Support Services\") " ascii
    $s10 = "* Separation of Components. The SOFTWARE PRODUCT is licensed as a single product. Neither it nor its component parts (including," ascii
    $s11 = "* Separation of Components. The SOFTWARE PRODUCT is licensed as a single product. Neither it nor its component parts (including," ascii
    $s12 = "e at DFARS 252.227-7013 or subparagraphs (c)(1) and (2) of the Commercial Computer Software - Restricted Rights at 48 CFR 52.227" ascii
    $s13 = "* Rental. You may not rent, lease or sell the SOFTWARE PRODUCT as a standalone component." fullword ascii
    $s14 = "IMPORTANT - READ CAREFULLY:" fullword ascii
    $s15 = "The SOFTWARE PRODUCT and documentation are provided with RESTRICTED RIGHTS. Use, duplication, or disclosure by the U.S.Governmen" ascii
    $s16 = "This Mead & Company Personal License Agreement (\"PLA\") is a legal agreement between you (either an individual or a single enti" ascii
    $s17 = ") and Mead & Company Limited for the Mead & Company software product identified above, which includes computer software and asso" ascii
    $s18 = "* Limitations on Reverse-Engineering, Decompilation, and Disassembly. You may not reverse-engineer, decompile, or disassemble th" ascii
    $s19 = "* Limitations on Reverse-Engineering, Decompilation, and Disassembly. You may not reverse-engineer, decompile, or disassemble th" ascii
    $s20 = "* Applications Software. You may install and use MULTIPLE copies of the SOFTWARE PRODUCT on multiple computers, and copy the \"S" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}