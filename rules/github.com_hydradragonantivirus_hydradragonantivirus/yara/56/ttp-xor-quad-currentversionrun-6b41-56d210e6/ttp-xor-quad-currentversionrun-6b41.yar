rule TTP_XOR_QUAD_CurrentVersionRun_6b41 {
  strings:
    $key_6b41 = { 38 2e [2] 1c 20 [2] 37 0c [2] 19 2e [2] 0d 35 [2] 02 2f [2] 1c 32 [2] 1e 33 [2] 05 35 [2] 19 32 [2] 05 1d }

  condition:
    any of them
}