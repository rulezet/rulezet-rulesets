rule TTP_XOR_QUAD_CurrentVersionRun_e56a {
  strings:
    $key_e56a = { b6 05 [2] 92 0b [2] b9 27 [2] 97 05 [2] 83 1e [2] 8c 04 [2] 92 19 [2] 90 18 [2] 8b 1e [2] 97 19 [2] 8b 36 }

  condition:
    any of them
}