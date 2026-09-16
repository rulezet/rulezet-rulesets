rule TTP_XOR_QUAD_CurrentVersionRun_e556 {
  strings:
    $key_e556 = { b6 39 [2] 92 37 [2] b9 1b [2] 97 39 [2] 83 22 [2] 8c 38 [2] 92 25 [2] 90 24 [2] 8b 22 [2] 97 25 [2] 8b 0a }

  condition:
    any of them
}