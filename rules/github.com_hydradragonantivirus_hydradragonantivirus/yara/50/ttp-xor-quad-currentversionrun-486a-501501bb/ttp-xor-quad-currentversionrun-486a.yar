rule TTP_XOR_QUAD_CurrentVersionRun_486a {
  strings:
    $key_486a = { 1b 05 [2] 3f 0b [2] 14 27 [2] 3a 05 [2] 2e 1e [2] 21 04 [2] 3f 19 [2] 3d 18 [2] 26 1e [2] 3a 19 [2] 26 36 }

  condition:
    any of them
}