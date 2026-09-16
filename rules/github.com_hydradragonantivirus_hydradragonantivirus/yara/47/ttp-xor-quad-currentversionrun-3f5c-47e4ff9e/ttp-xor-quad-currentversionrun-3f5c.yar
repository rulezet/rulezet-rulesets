rule TTP_XOR_QUAD_CurrentVersionRun_3f5c {
  strings:
    $key_3f5c = { 6c 33 [2] 48 3d [2] 63 11 [2] 4d 33 [2] 59 28 [2] 56 32 [2] 48 2f [2] 4a 2e [2] 51 28 [2] 4d 2f [2] 51 00 }

  condition:
    any of them
}