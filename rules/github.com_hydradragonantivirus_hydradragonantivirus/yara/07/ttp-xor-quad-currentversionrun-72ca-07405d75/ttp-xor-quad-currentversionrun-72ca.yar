rule TTP_XOR_QUAD_CurrentVersionRun_72ca {
  strings:
    $key_72ca = { 21 a5 [2] 05 ab [2] 2e 87 [2] 00 a5 [2] 14 be [2] 1b a4 [2] 05 b9 [2] 07 b8 [2] 1c be [2] 00 b9 [2] 1c 96 }

  condition:
    any of them
}