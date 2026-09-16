rule TTP_XOR_QUAD_CurrentVersionRun_72e9 {
  strings:
    $key_72e9 = { 21 86 [2] 05 88 [2] 2e a4 [2] 00 86 [2] 14 9d [2] 1b 87 [2] 05 9a [2] 07 9b [2] 1c 9d [2] 00 9a [2] 1c b5 }

  condition:
    any of them
}