rule TTP_XOR_QUAD_CurrentVersionRun_517d {
  strings:
    $key_517d = { 02 12 [2] 26 1c [2] 0d 30 [2] 23 12 [2] 37 09 [2] 38 13 [2] 26 0e [2] 24 0f [2] 3f 09 [2] 23 0e [2] 3f 21 }

  condition:
    any of them
}