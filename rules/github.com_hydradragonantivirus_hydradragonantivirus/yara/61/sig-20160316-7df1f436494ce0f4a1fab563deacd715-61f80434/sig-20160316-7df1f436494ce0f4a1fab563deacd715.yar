rule sig_20160316_7df1f436494ce0f4a1fab563deacd715 {
  meta:
    description = "datamaliciousorder - file 20160316_7df1f436494ce0f4a1fab563deacd715.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91d377ee2119ab7283107dd0fb3ede3ab5650557eafc0d343e757004990f335f"

  strings:
    $s1 = "while (RzuKI[ijiTCxzKw + wXrHCSfpq + xYy + xsWrrcmLjpIA + hRKpUfaWXnJxkzX] < 4 ) {WScript[ewch + XFCQuTI](1000)};" fullword ascii
    $s2 = "RzuKI[OKiBZBCPk + ZvIpedZqk + yalcKXjnhzdilk](uZPjtQVO, jgVDVluCpLGNYBd + UnkUuqIWDJvsHP + lYRS + hTYdLLOYimh + cyzlPptIIV + PPV" ascii
    $s3 = "function euPvqId(n){return kbzZdtKJGGPzIkD + MDo + ZeHpkphmOjQ + EPhNX + WgqBCIPIOkiIp + lQuHORtuRx + JWSyZBOXs + JatyPGc + zpKb" ascii
    $s4 = "function wRrwEhKYjge(IbaTVvYbjxlGxe){ALoaTDZUE[pnJzcxN + ZnhNTvXIfRMME + bwBjrFOG](IbaTVvYbjxlGxe, 0, 0);}" fullword ascii
    $s5 = "function euPvqId(n){return kbzZdtKJGGPzIkD + MDo + ZeHpkphmOjQ + EPhNX + WgqBCIPIOkiIp + lQuHORtuRx + JWSyZBOXs + JatyPGc + zpKb" ascii
    $s6 = " + FOAQYivzu, false);" fullword ascii
    $s7 = "var EyTGQa = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}