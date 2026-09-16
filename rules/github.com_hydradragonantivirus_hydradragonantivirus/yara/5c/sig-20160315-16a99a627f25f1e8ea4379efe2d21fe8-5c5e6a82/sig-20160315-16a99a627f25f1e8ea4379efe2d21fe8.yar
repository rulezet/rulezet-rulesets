rule sig_20160315_16a99a627f25f1e8ea4379efe2d21fe8 {
  meta:
    description = "datamaliciousorder - file 20160315_16a99a627f25f1e8ea4379efe2d21fe8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "654e08d7ef017485c3d6311d4e892aa5de4c8da263ddf6b78532bd41a7d05123"

  strings:
    $s1 = "function WBpXneQWe(Vzhu){WshShell[HcQFdSythm + zDUP](Vzhu, 0, 0);}" fullword ascii
    $s2 = "while (LFVfqnysnsCC.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "var ezeVilyo = new Date();" fullword ascii
    $s4 = "xJaThp + Ghs0 + dZq + mbuoaf + cLUj + sFfhYfXEgchNwm, false);" fullword ascii
    $s5 = "LFVfqnysnsCC[Mvubioc + sntCJ + DSaX](GLRVwClh, aEt + DhpJleAxy + kzdroZIq + tzMoMJqEY + jCbVgTFqXGb + cIP + FNFyOwkpDhu + gENpjK" ascii
    $s6 = "function WUuOpNDDtN(n){return oRpAhCgOZKl + GZVxyDtQdkoyeHP + IdMKYLv + drkcpD + ElYVCVDlXlYRFie + QCXin + JWXdi;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}