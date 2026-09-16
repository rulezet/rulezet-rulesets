rule TTP_XOR_QUAD_CurrentVersionRun_e518 {
  strings:
    $key_e518 = { b6 77 [2] 92 79 [2] b9 55 [2] 97 77 [2] 83 6c [2] 8c 76 [2] 92 6b [2] 90 6a [2] 8b 6c [2] 97 6b [2] 8b 44 }

  condition:
    any of them
}