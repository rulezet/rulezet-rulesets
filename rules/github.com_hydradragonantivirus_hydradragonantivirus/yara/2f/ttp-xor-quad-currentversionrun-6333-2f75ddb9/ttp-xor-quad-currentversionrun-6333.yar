rule TTP_XOR_QUAD_CurrentVersionRun_6333 {
  strings:
    $key_6333 = { 30 5c [2] 14 52 [2] 3f 7e [2] 11 5c [2] 05 47 [2] 0a 5d [2] 14 40 [2] 16 41 [2] 0d 47 [2] 11 40 [2] 0d 6f }

  condition:
    any of them
}