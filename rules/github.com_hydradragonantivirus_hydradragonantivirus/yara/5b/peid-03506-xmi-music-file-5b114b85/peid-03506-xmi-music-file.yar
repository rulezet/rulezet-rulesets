rule PEiD_03506_XMI_music_file_ {
  meta:
    description = "[XMI music file]"
    ep_only     = "false"

  strings:
    $a = { 46 4F 52 4D ?? ?? ?? ?? 58 4D 49 44 }

  condition:
    $a
}