rule SUSP_LNX_ARCH_Install_Hook_Jun26_RID3244: DEMO LINUX SUSP {
  meta:
    description = "Detects suspicious pre and post hooks in Arch install files"
    author      = "Marius Benthin"
    reference   = "https://www.sonatype.com/blog/atomic-arch-npm-campaign-adds-malicious-dependency"
    date        = "2026-06-15 13:57:51"
    score       = 70
    customer    = "demo"
    license     = "CC-BY-NC https://creativecommons.org/licenses/by-nc/4.0/"

    tags         = "DEMO, LINUX, SUSP"
    minimum_yara = "3.5.0"

  strings:
    $sa1 = "pre_install() {"
    $sa2 = "post_install() {"
    $sa3 = "pre_upgrade() {"
    $sa4 = "post_upgrade() {"
    $sa5 = "pre_remove() {"
    $sa6 = "post_remove() {"
    $sb1 = "npm install "
    $sb2 = "&& 'b''u''n'"
    $fp1 = "#!/bin/sh"

  condition:
    filesize < 5KB and 1 of ($sa*) and 1 of ($sb*) and not 1 of ($fp*)
}