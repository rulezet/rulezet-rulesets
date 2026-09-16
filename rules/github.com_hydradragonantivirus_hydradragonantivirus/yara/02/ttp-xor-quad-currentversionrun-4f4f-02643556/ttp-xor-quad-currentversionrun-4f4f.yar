rule TTP_XOR_QUAD_CurrentVersionRun_4f4f {
  strings:
    $key_4f4f = { 1c 20 [2] 38 2e [2] 13 02 [2] 3d 20 [2] 29 3b [2] 26 21 [2] 38 3c [2] 3a 3d [2] 21 3b [2] 3d 3c [2] 21 13 }

  condition:
    any of them
}