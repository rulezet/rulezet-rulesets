rule TTP_XOR_QUAD_CurrentVersionRun_f2f9 {
  strings:
    $key_f2f9 = { a1 96 [2] 85 98 [2] ae b4 [2] 80 96 [2] 94 8d [2] 9b 97 [2] 85 8a [2] 87 8b [2] 9c 8d [2] 80 8a [2] 9c a5 }

  condition:
    any of them
}