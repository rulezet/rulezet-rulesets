rule TTP_XOR_QUAD_CurrentVersionRun_6d6a {
  strings:
    $key_6d6a = { 3e 05 [2] 1a 0b [2] 31 27 [2] 1f 05 [2] 0b 1e [2] 04 04 [2] 1a 19 [2] 18 18 [2] 03 1e [2] 1f 19 [2] 03 36 }

  condition:
    any of them
}