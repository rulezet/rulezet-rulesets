rule sig_20160525_66cb8c19d059753a467e4bc49d47bf30 {
  meta:
    description = "datamaliciousorder - file 20160525_66cb8c19d059753a467e4bc49d47bf30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e570f1295a30b79590495432e568a7246ff34d18a30da3dcaeeefb0eb489cd90"

  strings:
    $s1 = "lock rav\\n;\"86x\\\\t\" = mk rav\\n;\"e37x\\\\\" = gedotdark rav\\n;\"46x\\\\n\" = keppelk rav\\n;\"l35x\\\\\" = modnark rav\\n" ascii
    $s2 = "lcitrape noitcnuf( + eixode+cthd + )tsilslianbmuhtod(rerednerd+ssorcad + sdnetd+)ecapsetihwxelfd(modnard+keppeld+gedotdard+)suid" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}