rule TTP_XOR_QUAD_CurrentVersionRun_4f7f {
  strings:
    $key_4f7f = { 1c 10 [2] 38 1e [2] 13 32 [2] 3d 10 [2] 29 0b [2] 26 11 [2] 38 0c [2] 3a 0d [2] 21 0b [2] 3d 0c [2] 21 23 }

  condition:
    any of them
}