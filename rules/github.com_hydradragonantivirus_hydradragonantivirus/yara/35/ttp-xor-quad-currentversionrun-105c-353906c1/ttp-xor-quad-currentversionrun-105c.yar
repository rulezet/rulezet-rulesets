rule TTP_XOR_QUAD_CurrentVersionRun_105c {
  strings:
    $key_105c = { 43 33 [2] 67 3d [2] 4c 11 [2] 62 33 [2] 76 28 [2] 79 32 [2] 67 2f [2] 65 2e [2] 7e 28 [2] 62 2f [2] 7e 00 }

  condition:
    any of them
}