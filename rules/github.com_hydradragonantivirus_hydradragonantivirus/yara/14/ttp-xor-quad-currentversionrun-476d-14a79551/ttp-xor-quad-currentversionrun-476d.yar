rule TTP_XOR_QUAD_CurrentVersionRun_476d {
  strings:
    $key_476d = { 14 02 [2] 30 0c [2] 1b 20 [2] 35 02 [2] 21 19 [2] 2e 03 [2] 30 1e [2] 32 1f [2] 29 19 [2] 35 1e [2] 29 31 }

  condition:
    any of them
}