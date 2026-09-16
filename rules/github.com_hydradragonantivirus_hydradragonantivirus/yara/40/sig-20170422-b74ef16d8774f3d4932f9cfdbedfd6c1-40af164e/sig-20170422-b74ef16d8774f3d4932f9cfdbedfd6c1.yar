rule sig_20170422_b74ef16d8774f3d4932f9cfdbedfd6c1 {
  meta:
    description = "datamaliciousorder - file 20170422_b74ef16d8774f3d4932f9cfdbedfd6c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4caf3d4c5f07bf7e814fc509dc17be340044611b9640cdfd8ee301172db80629"

  strings:
    $s1 = "if (SrBXmzGxlesOhRAd.FolderExists(ioabFQsYuAOHwnPT) == true) {" fullword ascii
    $s2 = "function juPCDGdkgTivIHnMSK(rWAtsndTiHyaFgKxw) { return String.fromCharCode(rWAtsndTiHyaFgKxw); }" fullword ascii
    $s3 = "return zrKQkoXfuEMOgcxV.split(uEmGxVPbYLINyfwnd).join(\"\"); }" fullword ascii
    $s4 = "function iYMsdQrOaTAcVPDlhLy(zrKQkoXfuEMOgcxV, uEmGxVPbYLINyfwnd) { " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}