rule TTP_XOR_QUAD_CurrentVersionRun_245c {
  strings:
    $key_245c = { 77 33 [2] 53 3d [2] 78 11 [2] 56 33 [2] 42 28 [2] 4d 32 [2] 53 2f [2] 51 2e [2] 4a 28 [2] 56 2f [2] 4a 00 }

  condition:
    any of them
}