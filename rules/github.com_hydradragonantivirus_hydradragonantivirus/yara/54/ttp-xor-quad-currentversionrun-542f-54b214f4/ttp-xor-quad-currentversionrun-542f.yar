rule TTP_XOR_QUAD_CurrentVersionRun_542f {
  strings:
    $key_542f = { 07 40 [2] 23 4e [2] 08 62 [2] 26 40 [2] 32 5b [2] 3d 41 [2] 23 5c [2] 21 5d [2] 3a 5b [2] 26 5c [2] 3a 73 }

  condition:
    any of them
}