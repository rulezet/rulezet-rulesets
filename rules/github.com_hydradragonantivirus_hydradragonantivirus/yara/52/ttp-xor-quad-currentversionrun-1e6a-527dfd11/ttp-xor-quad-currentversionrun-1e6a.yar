rule TTP_XOR_QUAD_CurrentVersionRun_1e6a {
  strings:
    $key_1e6a = { 4d 05 [2] 69 0b [2] 42 27 [2] 6c 05 [2] 78 1e [2] 77 04 [2] 69 19 [2] 6b 18 [2] 70 1e [2] 6c 19 [2] 70 36 }

  condition:
    any of them
}