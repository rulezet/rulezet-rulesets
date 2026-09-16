rule TTP_XOR_QUAD_CurrentVersionRun_375c {
  strings:
    $key_375c = { 64 33 [2] 40 3d [2] 6b 11 [2] 45 33 [2] 51 28 [2] 5e 32 [2] 40 2f [2] 42 2e [2] 59 28 [2] 45 2f [2] 59 00 }

  condition:
    any of them
}