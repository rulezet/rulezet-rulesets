rule PEiD_02494_vfp_exeNc_V5_00____Wang_JianGuo_ {
  meta:
    description = "[vfp&exeNc V5.00 -> Wang JianGuo]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5D ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 CC }

  condition:
    $a
}