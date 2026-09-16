rule TTP_XOR_QUAD_CurrentVersionRun_e568 {
  strings:
    $key_e568 = { b6 07 [2] 92 09 [2] b9 25 [2] 97 07 [2] 83 1c [2] 8c 06 [2] 92 1b [2] 90 1a [2] 8b 1c [2] 97 1b [2] 8b 34 }

  condition:
    any of them
}