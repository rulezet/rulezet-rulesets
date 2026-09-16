rule PEiD_00521_Encrypted_by__RSCC_286_v1_01_ {
  meta:
    description = "[Encrypted by? RSCC/286 v1.01]"
    ep_only     = "false"

  strings:
    $a = { FE 52 53 43 43 2F 31 2E 30 31 FE }

  condition:
    $a
}