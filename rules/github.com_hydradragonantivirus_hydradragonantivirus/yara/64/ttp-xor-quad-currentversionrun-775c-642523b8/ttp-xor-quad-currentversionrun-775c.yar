rule TTP_XOR_QUAD_CurrentVersionRun_775c {
  strings:
    $key_775c = { 24 33 [2] 00 3d [2] 2b 11 [2] 05 33 [2] 11 28 [2] 1e 32 [2] 00 2f [2] 02 2e [2] 19 28 [2] 05 2f [2] 19 00 }

  condition:
    any of them
}