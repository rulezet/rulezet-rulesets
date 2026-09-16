rule TTP_XOR_QUAD_CurrentVersionRun_6e1c {
  strings:
    $key_6e1c = { 3d 73 [2] 19 7d [2] 32 51 [2] 1c 73 [2] 08 68 [2] 07 72 [2] 19 6f [2] 1b 6e [2] 00 68 [2] 1c 6f [2] 00 40 }

  condition:
    any of them
}