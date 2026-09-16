rule TTP_XOR_QUAD_CurrentVersionRun_e54a {
  strings:
    $key_e54a = { b6 25 [2] 92 2b [2] b9 07 [2] 97 25 [2] 83 3e [2] 8c 24 [2] 92 39 [2] 90 38 [2] 8b 3e [2] 97 39 [2] 8b 16 }

  condition:
    any of them
}