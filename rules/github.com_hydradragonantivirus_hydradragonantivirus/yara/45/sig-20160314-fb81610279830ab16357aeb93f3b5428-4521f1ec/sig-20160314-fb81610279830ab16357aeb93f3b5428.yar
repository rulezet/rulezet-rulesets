rule sig_20160314_fb81610279830ab16357aeb93f3b5428 {
  meta:
    description = "datamaliciousorder - file 20160314_fb81610279830ab16357aeb93f3b5428.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d14b1497e09dc92e8d75bc1279d3948c761f457b9b9f5ceab76888e5f2893969"

  strings:
    $s1 = "while (BBHKNn.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "return Xdc + fonicMvv + KSDj + bzHPYOPyFfvn + WkDtEXoR + DvFVFAYRIlFI + pyxfHnprzCEgLb" fullword ascii
    $s3 = "B + MYFfoP + VPWxiIVmcJn + MUsonu + gcEwDxjSAm + EIWGZwGAE, false);" fullword ascii
    $s4 = "BBHKNn.open(QKFcdSU + YKK, mynWLzpYZKQ + wHsVmE + SEqeBLw + jSpIZEQ + CJBiCVJgCsQj + bnP + CjaoAAb + RSWXFgZcjTcRrv + hefvNhWvcY" ascii
    $s5 = "function BrpendfUzQaZzY(fname)" fullword ascii
    $s6 = "var Ouptq = new Date();" fullword ascii
    $s7 = "function OFZuuzcpnfNw(n)" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}