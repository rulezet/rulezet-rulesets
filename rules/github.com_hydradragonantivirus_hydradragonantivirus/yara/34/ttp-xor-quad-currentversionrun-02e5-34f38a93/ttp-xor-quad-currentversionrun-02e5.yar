rule TTP_XOR_QUAD_CurrentVersionRun_02e5 {
  strings:
    $key_02e5 = { 51 8a [2] 75 84 [2] 5e a8 [2] 70 8a [2] 64 91 [2] 6b 8b [2] 75 96 [2] 77 97 [2] 6c 91 [2] 70 96 [2] 6c b9 }

  condition:
    any of them
}