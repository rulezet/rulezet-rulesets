rule TTP_XOR_QUAD_CurrentVersionRun_6efc {
  strings:
    $key_6efc = { 3d 93 [2] 19 9d [2] 32 b1 [2] 1c 93 [2] 08 88 [2] 07 92 [2] 19 8f [2] 1b 8e [2] 00 88 [2] 1c 8f [2] 00 a0 }

  condition:
    any of them
}