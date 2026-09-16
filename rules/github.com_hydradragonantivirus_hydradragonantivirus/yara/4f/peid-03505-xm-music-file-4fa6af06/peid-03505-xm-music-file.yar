rule PEiD_03505_XM_music_file_ {
  meta:
    description = "[XM music file]"
    ep_only     = "false"

  strings:
    $a = "Extended Module:"

  condition:
    $a
}