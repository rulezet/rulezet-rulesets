rule TTP_XOR_QUAD_CurrentVersionRun_6e4f {
  strings:
    $key_6e4f = { 3d 20 [2] 19 2e [2] 32 02 [2] 1c 20 [2] 08 3b [2] 07 21 [2] 19 3c [2] 1b 3d [2] 00 3b [2] 1c 3c [2] 00 13 }

  condition:
    any of them
}