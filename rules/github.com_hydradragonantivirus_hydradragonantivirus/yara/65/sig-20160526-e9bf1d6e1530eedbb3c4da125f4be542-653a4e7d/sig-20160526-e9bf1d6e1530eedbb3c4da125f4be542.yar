rule sig_20160526_e9bf1d6e1530eedbb3c4da125f4be542 {
  meta:
    description = "datamaliciousorder - file 20160526_e9bf1d6e1530eedbb3c4da125f4be542.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bfb5d99c620b0a049adca37552f38b1c0e96d279f77a4532b73dd507c8a86f5"

  strings:
    $s1  = "Math.cos(13), 2) - 1))-271) | pGmgZZ;jNVkzzPNK = InhWRjHuzRZCZoSCXFewbKAF>> (860 + Math.round((Math.pow(Math.sin(910), 2) + Math" ascii
    $s2  = "ath.round((Math.pow(Math.sin(592), 2) + Math.pow(Math.cos(592), 2) - 1))-420) | femlFhkBltDLcu<< (32 + Math.round((Math.pow(Math" ascii
    $s3  = ".pow(Math.cos(910), 2) - 1))-844) & 0xff;FBnxo = InhWRjHuzRZCZoSCXFewbKAF>> (183 + Math.round((Math.pow(Math.sin(292), 2) + Math" ascii
    $s4  = "function wcmqNT(dNvaHsFryeqqP) {var kkSmhYuKtQeJic = vPVeLHtFfBNDGa.join(mhHGxbnoD[0]);var jNVkzzPNK, FBnxo, UxCrcUyKVRAqSoTuWk," ascii
    $s5  = ".pow(Math.cos(292), 2) - 1))-175) & 0xff;UxCrcUyKVRAqSoTuWk = InhWRjHuzRZCZoSCXFewbKAF & 0xff;if (lFLNDxgLhJGpUP == (978 + Math." ascii
    $s6  = "round((Math.pow(Math.sin(150), 2) + Math.pow(Math.cos(150), 2) - 1))-914)) LHdqRDWpHZOnRpzWcJoE += f(jNVkzzPNK);else if (pGmgZZ " ascii
    $s7  = "function XUVYfR(HUFUlErc,TYKTYvxOHxWYJMcIDey){return HUFUlErc.charAt(TYKTYvxOHxWYJMcIDey);}" fullword ascii
    $s8  = "function f(vsWasJFdDMewWuNbzX){return String.fromCharCode(vsWasJFdDMewWuNbzX);}" fullword ascii
    $s9  = "function auwuJiVDZjteKtDLFdpfJNJQ(MGfgCbUkAowMZFrLnI,tzcJPkvqEeK){return MGfgCbUkAowMZFrLnI.indexOf(tzcJPkvqEeK);}" fullword ascii
    $s10 = "function TccsBcwUwQysODeYQIvhiXea(hWwhlBhQbvMJePG,HAhYYYASyaayzvOeELCfSH){return String.fromCharCode(hWwhlBhQbvMJePG,HAhYYYASyaa" ascii
    $s11 = "function TccsBcwUwQysODeYQIvhiXea(hWwhlBhQbvMJePG,HAhYYYASyaayzvOeELCfSH){return String.fromCharCode(hWwhlBhQbvMJePG,HAhYYYASyaa" ascii
    $s12 = "function lwCDluYFpdnKQG(bkJifaO,FfontRSQgLJzVHkZfDj,vWIFuBH){return String.fromCharCode(bkJifaO,FfontRSQgLJzVHkZfDj,vWIFuBH);}" fullword ascii
    $s13 = "YqKOAiEJLWeF < dNvaHsFryeqqP.length);return LHdqRDWpHZOnRpzWcJoE;}" fullword ascii
    $s14 = "function wcmqNT(dNvaHsFryeqqP) {var kkSmhYuKtQeJic = vPVeLHtFfBNDGa.join(mhHGxbnoD[0]);var jNVkzzPNK, FBnxo, UxCrcUyKVRAqSoTuWk," ascii
    $s15 = "IvhiXea(jNVkzzPNK, FBnxo);else LHdqRDWpHZOnRpzWcJoE += lwCDluYFpdnKQG(jNVkzzPNK, FBnxo, UxCrcUyKVRAqSoTuWk);} while (eJTOiYfxFUk" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}