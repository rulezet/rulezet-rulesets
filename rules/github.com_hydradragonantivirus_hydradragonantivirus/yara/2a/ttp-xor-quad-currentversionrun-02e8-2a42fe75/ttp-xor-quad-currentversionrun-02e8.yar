rule TTP_XOR_QUAD_CurrentVersionRun_02e8 {
  strings:
    $key_02e8 = { 51 87 [2] 75 89 [2] 5e a5 [2] 70 87 [2] 64 9c [2] 6b 86 [2] 75 9b [2] 77 9a [2] 6c 9c [2] 70 9b [2] 6c b4 }

  condition:
    any of them
}