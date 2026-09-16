rule TTP_XOR_QUAD_CurrentVersionRun_6e1f {
  strings:
    $key_6e1f = { 3d 70 [2] 19 7e [2] 32 52 [2] 1c 70 [2] 08 6b [2] 07 71 [2] 19 6c [2] 1b 6d [2] 00 6b [2] 1c 6c [2] 00 43 }

  condition:
    any of them
}