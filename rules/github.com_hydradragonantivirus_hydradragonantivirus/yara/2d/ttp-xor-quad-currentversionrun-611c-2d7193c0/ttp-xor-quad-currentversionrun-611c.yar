rule TTP_XOR_QUAD_CurrentVersionRun_611c {
  strings:
    $key_611c = { 32 73 [2] 16 7d [2] 3d 51 [2] 13 73 [2] 07 68 [2] 08 72 [2] 16 6f [2] 14 6e [2] 0f 68 [2] 13 6f [2] 0f 40 }

  condition:
    any of them
}