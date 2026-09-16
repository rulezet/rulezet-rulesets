rule sig_20170127_ac02f835cc57f3f58c788eb66d607275 {
  meta:
    description = "datamaliciousorder - file 20170127_ac02f835cc57f3f58c788eb66d607275.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2db838a4bea1e2ce8b496e966ac942fb220ed97f9c82a11421d75fc3d22b21df"

  strings:
    $s1 = "hzaqygu5 = this[[\"rizny\", \"pemnibbu\", [\"xypa\", \"WS\", \"puher\"], \"xzagjon\", \"gawy\", \"axuls\", \"ifegy\", \"qafgyj\"" ascii
    $s2 = ", \"zehjujc\"], \"cbumo\", \"odgubqern\", \"ahmuqji\"][7][0] + [\"sofku\", \"ohuv\", \"roqvipe\", \"egzedpo\", [\"wxemtu\", \"te" ascii
    $s3 = "//if ([\"ehresfyw\", \"ywtobevt\", \"osixyqg\", \"irece\", new Function([\"cinsil\", \"igodos\", \"gxyple\", \"ifwekr\", \"cycze" ascii
    $s4 = "//if ([\"ehresfyw\", \"ywtobevt\", \"osixyqg\", \"irece\", new Function([\"cinsil\", \"igodos\", \"gxyple\", \"ifwekr\", \"cycze" ascii
    $s5 = "hzaqygu5 = this[[\"rizny\", \"pemnibbu\", [\"xypa\", \"WS\", \"puher\"], \"xzagjon\", \"gawy\", \"axuls\", \"ifegy\", \"qafgyj\"" ascii

  condition:
    uint16(0) == 0x2f2f and
    all of them
}