rule PEiD_01541_PECompact_2_0beta_student_version____Jeremy_Collake_ {
  meta:
    description = "[PECompact 2.0beta/student version -> Jeremy Collake]"
    ep_only     = "false"

  strings:
    $a = { B8 ?? ?? ?? EE 05 12 13 13 12 50 64 FF 35 00 00 00 00 64 89 25 00 }

  condition:
    $a
}