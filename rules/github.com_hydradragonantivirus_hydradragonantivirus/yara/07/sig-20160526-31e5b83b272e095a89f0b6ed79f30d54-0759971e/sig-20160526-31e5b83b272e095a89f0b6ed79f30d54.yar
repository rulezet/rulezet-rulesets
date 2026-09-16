rule sig_20160526_31e5b83b272e095a89f0b6ed79f30d54 {
  meta:
    description = "datamaliciousorder - file 20160526_31e5b83b272e095a89f0b6ed79f30d54.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d10328b1611d95e6b6c420c11b91fa56f17613d153e0168a7c1d1f0968e6faf9"

  strings:
    $s1  = "ath.pow(Math.sin(349), 2) + Math.pow(Math.cos(349), 2) - 1))-766)) SyjtIOVargKUn += lD(KzihlunKL);else if (SehzmBzoLdOkRtLFAkSH " ascii
    $s2  = " Math.round((Math.pow(Math.sin(695), 2) + Math.pow(Math.cos(695), 2) - 1))-737) | WqnTZTFBLq<< (276 + Math.round((Math.pow(Math." ascii
    $s3  = "function SAQpOIZpfOC(CcEUfaxhmWsnm) {var qzbKmfurXshSZC = szYnLWLM.join(qveaMkTOAkENPUUqzp[0]);var KzihlunKL, NduEnOyga, cAfBwle" ascii
    $s4  = "function ruSWcGmCkYGWogQ(KLXcjhXqqRnAkOLAJQPZ,utrXUkSNINkKqKyqTqUAZjsc){return KLXcjhXqqRnAkOLAJQPZ.charAt(utrXUkSNINkKqKyqTqUAZ" ascii
    $s5  = "function ruSWcGmCkYGWogQ(KLXcjhXqqRnAkOLAJQPZ,utrXUkSNINkKqKyqTqUAZjsc){return KLXcjhXqqRnAkOLAJQPZ.charAt(utrXUkSNINkKqKyqTqUAZ" ascii
    $s6  = "function wsskUErv(cqCvUVuJlDWO,BwHhQjDSAMSAlSUJee,oOhuCQNGRygDYwNLYRPOa){return String.fromCharCode(cqCvUVuJlDWO,BwHhQjDSAMSAlSU" ascii
    $s7  = "function wsskUErv(cqCvUVuJlDWO,BwHhQjDSAMSAlSUJee,oOhuCQNGRygDYwNLYRPOa){return String.fromCharCode(cqCvUVuJlDWO,BwHhQjDSAMSAlSU" ascii
    $s8  = "function jHVwlPKFUOxbBvZaGznxRGiT(KJEjvmLhOpcgZuvLpPrwsPf,eyqglt){return KJEjvmLhOpcgZuvLpPrwsPf.indexOf(eyqglt);}" fullword ascii
    $s9  = "ngth);return SyjtIOVargKUn;}" fullword ascii
    $s10 = "function lD(GqSyeRoj){return String.fromCharCode(GqSyeRoj);}" fullword ascii
    $s11 = "function RyyNyXj(AWyNnPwXUlSERLotvRWrCGv,kzymY){return String.fromCharCode(AWyNnPwXUlSERLotvRWrCGv,kzymY);}" fullword ascii
    $s12 = "function SAQpOIZpfOC(CcEUfaxhmWsnm) {var qzbKmfurXshSZC = szYnLWLM.join(qveaMkTOAkENPUUqzp[0]);var KzihlunKL, NduEnOyga, cAfBwle" ascii
    $s13 = "duEnOyga);else SyjtIOVargKUn += wsskUErv(KzihlunKL, NduEnOyga, cAfBwlekTIstkTzLBz);} while (wnuIBOppdlZBAqieM < CcEUfaxhmWsnm.le" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}