rule mal_macos_pureland: stealer_0xfff {
  meta:
    description = "Identify macOS PureLand crypto stealer."
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.04"
    sample      = "82633f6fec78560d657f6eda76d11a57c5747030847b3bc14766cec7d33d42be"
    DaysofYARA  = "63/100"
    DaysofYARA  = "67/100"

  strings:
    $s0 = "system_profiler SPHardwareDataType > /Users/"
    $s1 = "security 2>&1 > /dev/null find-generic-password -ga 'Chrome' | awk '{print $2}' > /Users/"
    $s2 = "/Library/Application Support/Exodus/exodus.wallet/"      $s3 = "/.dkdbsqtl/vakkdsr"  
    $ext0 = "nkbihfbeogaeaoehlefnkodbefgpgknn"      $ext1 = "bfnaelmomeimhlpmgjnjophhpkkoljpa"      $ext2 = "ibnejdfjmmkpcnlpebklmnkoeoihofec"      $ext3 = "efbglgofoippbgcjepnhiblaibcnclgk"  
  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    60 % of them
}