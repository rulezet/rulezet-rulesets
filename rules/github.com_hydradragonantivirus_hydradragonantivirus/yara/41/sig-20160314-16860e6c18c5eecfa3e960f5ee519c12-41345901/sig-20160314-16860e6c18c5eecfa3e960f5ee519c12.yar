rule sig_20160314_16860e6c18c5eecfa3e960f5ee519c12 {
  meta:
    description = "datamaliciousorder - file 20160314_16860e6c18c5eecfa3e960f5ee519c12.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "012b46569278824744602a83e2f72e1a016d018449208cd8ee3f466cc2b78050"

  strings:
    $s1  = "RnNJmgPaYsf = WshShell[vrneBhfo + pFeAHBzDZrhVo + hFak + plUS + CoaQ + ngYG + gKbFUnXFr + zGbcSbbNAQtcoUY + CCTfqtJsuPoP + xLaPo" ascii
    $s2  = "RnNJmgPaYsf = WshShell[vrneBhfo + pFeAHBzDZrhVo + hFak + plUS + CoaQ + ngYG + gKbFUnXFr + zGbcSbbNAQtcoUY + CCTfqtJsuPoP + xLaPo" ascii
    $s3  = "cuzs.open(bKdzdvqkUrBr + jfQiFjZVIjviWX + aECiMCFDTJSaCD, cnj + EMjdzNlsq + kBG + gBri + mAuVXlhlMOWEk + qRwpiQQ + Hnz + DFMBBfM" ascii
    $s4  = "while (cuzs.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s5  = "TQCSuxd + okylpnqTU + FMJzrFqtwSxHkHr + kLCfKT + zDLwp + tKwnaTkB + DxHc + zRiSeAyqEKio + aZVkazrDnnRE + vkyPZZ + eSi, false);" fullword ascii
    $s6  = "function idKfysBJBkV(fname)" fullword ascii
    $s7  = "var plUS = \"En\";" fullword ascii
    $s8  = "var CWGS = new Date();" fullword ascii
    $s9  = "return tIeWkoFAfikI + WWLRKPIjTmRCF + SwxYfcvcda + LNZYlcaKm + AaZDo" fullword ascii
    $s10 = "function DfqyiSdSmAAbwnn(n)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}