rule TTP_XOR_QUAD_CurrentVersionRun_e569 {
  strings:
    $key_e569 = { b6 06 [2] 92 08 [2] b9 24 [2] 97 06 [2] 83 1d [2] 8c 07 [2] 92 1a [2] 90 1b [2] 8b 1d [2] 97 1a [2] 8b 35 }

  condition:
    any of them
}