rule TTP_XOR_QUAD_CurrentVersionRun_6eef {
  strings:
    $key_6eef = { 3d 80 [2] 19 8e [2] 32 a2 [2] 1c 80 [2] 08 9b [2] 07 81 [2] 19 9c [2] 1b 9d [2] 00 9b [2] 1c 9c [2] 00 b3 }

  condition:
    any of them
}