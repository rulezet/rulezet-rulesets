rule TTP_XOR_QUAD_CurrentVersionRun_46f9 {
  strings:
    $key_46f9 = { 15 96 [2] 31 98 [2] 1a b4 [2] 34 96 [2] 20 8d [2] 2f 97 [2] 31 8a [2] 33 8b [2] 28 8d [2] 34 8a [2] 28 a5 }

  condition:
    any of them
}