rule TTP_XOR_QUAD_CurrentVersionRun_e509 {
  strings:
    $key_e509 = { b6 66 [2] 92 68 [2] b9 44 [2] 97 66 [2] 83 7d [2] 8c 67 [2] 92 7a [2] 90 7b [2] 8b 7d [2] 97 7a [2] 8b 55 }

  condition:
    any of them
}