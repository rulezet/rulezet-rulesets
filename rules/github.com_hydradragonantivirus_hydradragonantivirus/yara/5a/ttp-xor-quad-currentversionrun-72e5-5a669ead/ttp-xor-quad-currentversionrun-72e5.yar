rule TTP_XOR_QUAD_CurrentVersionRun_72e5 {
  strings:
    $key_72e5 = { 21 8a [2] 05 84 [2] 2e a8 [2] 00 8a [2] 14 91 [2] 1b 8b [2] 05 96 [2] 07 97 [2] 1c 91 [2] 00 96 [2] 1c b9 }

  condition:
    any of them
}