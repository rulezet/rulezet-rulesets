rule TTP_XOR_QUAD_CurrentVersionRun_02f4 {
  strings:
    $key_02f4 = { 51 9b [2] 75 95 [2] 5e b9 [2] 70 9b [2] 64 80 [2] 6b 9a [2] 75 87 [2] 77 86 [2] 6c 80 [2] 70 87 [2] 6c a8 }

  condition:
    any of them
}