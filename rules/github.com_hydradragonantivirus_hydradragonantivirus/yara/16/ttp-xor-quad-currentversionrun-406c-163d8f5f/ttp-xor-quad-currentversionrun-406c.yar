rule TTP_XOR_QUAD_CurrentVersionRun_406c {
  strings:
    $key_406c = { 13 03 [2] 37 0d [2] 1c 21 [2] 32 03 [2] 26 18 [2] 29 02 [2] 37 1f [2] 35 1e [2] 2e 18 [2] 32 1f [2] 2e 30 }

  condition:
    any of them
}