rule sig_20170424_983ed9dcc3881751b2a48a51e3abc939 {
  meta:
    description = "datamaliciousorder - file 20170424_983ed9dcc3881751b2a48a51e3abc939.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c59aa3e48defd57e2ea1e8250bee294ea443b4d2bfc47249d55042ee0460cb64"

  strings:
    $s1 = "if (bVEFGroSdekQBhmW.FolderExists(\"C:\\\\w\"+\"iND\"+\"oWs\") == true) {" fullword ascii
    $s2 = "return ILzUBJQyDlbRqikmN.split(sgHDGucvkJWAzMRXV).join(elgKOFHpjukCEhbzAI); }" fullword ascii
    $s3 = "function UFyhbYPNaveSMtw(ILzUBJQyDlbRqikmN, sgHDGucvkJWAzMRXV, elgKOFHpjukCEhbzAI) { " fullword ascii
    $s4 = "\"n?scap?(\\\"var:20wsh:20:3D:20n?w:20Activ?XOb\"+" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}