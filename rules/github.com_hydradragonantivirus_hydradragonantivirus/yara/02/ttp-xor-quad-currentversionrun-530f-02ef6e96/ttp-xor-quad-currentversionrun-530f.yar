rule TTP_XOR_QUAD_CurrentVersionRun_530f {
  strings:
    $key_530f = { 00 60 [2] 24 6e [2] 0f 42 [2] 21 60 [2] 35 7b [2] 3a 61 [2] 24 7c [2] 26 7d [2] 3d 7b [2] 21 7c [2] 3d 53 }

  condition:
    any of them
}