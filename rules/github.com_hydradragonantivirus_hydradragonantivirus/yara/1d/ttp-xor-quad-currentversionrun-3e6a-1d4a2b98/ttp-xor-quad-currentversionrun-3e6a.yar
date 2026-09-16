rule TTP_XOR_QUAD_CurrentVersionRun_3e6a {
  strings:
    $key_3e6a = { 6d 05 [2] 49 0b [2] 62 27 [2] 4c 05 [2] 58 1e [2] 57 04 [2] 49 19 [2] 4b 18 [2] 50 1e [2] 4c 19 [2] 50 36 }

  condition:
    any of them
}