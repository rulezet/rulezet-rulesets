rule PEiD_01154_modified_HACKSTOP_v1_11f_ {
  meta:
    description = "[modified HACKSTOP v1.11f]"
    ep_only     = "true"

  strings:
    $a = { 52 B4 30 CD 21 52 FA ?? FB 3D ?? ?? EB ?? CD 20 0E 1F B4 09 E8 }

  condition:
    $a
}