rule TTP_XOR_QUAD_CurrentVersionRun_055c {
  strings:
    $key_055c = { 56 33 [2] 72 3d [2] 59 11 [2] 77 33 [2] 63 28 [2] 6c 32 [2] 72 2f [2] 70 2e [2] 6b 28 [2] 77 2f [2] 6b 00 }

  condition:
    any of them
}