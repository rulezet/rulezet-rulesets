rule TTP_XOR_QUAD_CurrentVersionRun_0b6a {
  strings:
    $key_0b6a = { 58 05 [2] 7c 0b [2] 57 27 [2] 79 05 [2] 6d 1e [2] 62 04 [2] 7c 19 [2] 7e 18 [2] 65 1e [2] 79 19 [2] 65 36 }

  condition:
    any of them
}