rule PEiD_00507_E_S_O__Eclipse_Operating_System_v_2_08___DOS_Extender_ {
  meta:
    description = "[E.S.O. Eclipse Operating System v.2.08 + DOS Extender]"
    ep_only     = "true"

  strings:
    $a = { 8C C8 8E D8 BA ?? ?? E8 ?? ?? BB ?? ?? 8C C0 2B D8 B4 4A CD 21 BA ?? ?? 73 ?? E9 }

  condition:
    $a
}