rule TTP_XOR_QUAD_CurrentVersionRun_72e8 {
  strings:
    $key_72e8 = { 21 87 [2] 05 89 [2] 2e a5 [2] 00 87 [2] 14 9c [2] 1b 86 [2] 05 9b [2] 07 9a [2] 1c 9c [2] 00 9b [2] 1c b4 }

  condition:
    any of them
}