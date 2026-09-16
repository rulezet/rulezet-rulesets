rule TTP_XOR_QUAD_CurrentVersionRun_e56b {
  strings:
    $key_e56b = { b6 04 [2] 92 0a [2] b9 26 [2] 97 04 [2] 83 1f [2] 8c 05 [2] 92 18 [2] 90 19 [2] 8b 1f [2] 97 18 [2] 8b 37 }

  condition:
    any of them
}