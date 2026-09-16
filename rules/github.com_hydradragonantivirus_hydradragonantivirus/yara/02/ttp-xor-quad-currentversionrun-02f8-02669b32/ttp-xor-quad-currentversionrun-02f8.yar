rule TTP_XOR_QUAD_CurrentVersionRun_02f8 {
  strings:
    $key_02f8 = { 51 97 [2] 75 99 [2] 5e b5 [2] 70 97 [2] 64 8c [2] 6b 96 [2] 75 8b [2] 77 8a [2] 6c 8c [2] 70 8b [2] 6c a4 }

  condition:
    any of them
}