rule TTP_XOR_QUAD_CurrentVersionRun_02e9 {
  strings:
    $key_02e9 = { 51 86 [2] 75 88 [2] 5e a4 [2] 70 86 [2] 64 9d [2] 6b 87 [2] 75 9a [2] 77 9b [2] 6c 9d [2] 70 9a [2] 6c b5 }

  condition:
    any of them
}