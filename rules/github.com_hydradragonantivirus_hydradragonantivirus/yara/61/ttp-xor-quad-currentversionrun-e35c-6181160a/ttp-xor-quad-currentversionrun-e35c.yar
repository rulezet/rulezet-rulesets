rule TTP_XOR_QUAD_CurrentVersionRun_e35c {
  strings:
    $key_e35c = { b0 33 [2] 94 3d [2] bf 11 [2] 91 33 [2] 85 28 [2] 8a 32 [2] 94 2f [2] 96 2e [2] 8d 28 [2] 91 2f [2] 8d 00 }

  condition:
    any of them
}