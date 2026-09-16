rule TTP_XOR_QUAD_CurrentVersionRun_205c {
  strings:
    $key_205c = { 73 33 [2] 57 3d [2] 7c 11 [2] 52 33 [2] 46 28 [2] 49 32 [2] 57 2f [2] 55 2e [2] 4e 28 [2] 52 2f [2] 4e 00 }

  condition:
    any of them
}