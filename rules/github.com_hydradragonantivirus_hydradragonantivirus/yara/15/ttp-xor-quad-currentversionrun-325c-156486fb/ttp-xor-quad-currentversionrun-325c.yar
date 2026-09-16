rule TTP_XOR_QUAD_CurrentVersionRun_325c {
  strings:
    $key_325c = { 61 33 [2] 45 3d [2] 6e 11 [2] 40 33 [2] 54 28 [2] 5b 32 [2] 45 2f [2] 47 2e [2] 5c 28 [2] 40 2f [2] 5c 00 }

  condition:
    any of them
}