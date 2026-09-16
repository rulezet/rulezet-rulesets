rule TTP_XOR_QUAD_CurrentVersionRun_1b71 {
  strings:
    $key_1b71 = { 48 1e [2] 6c 10 [2] 47 3c [2] 69 1e [2] 7d 05 [2] 72 1f [2] 6c 02 [2] 6e 03 [2] 75 05 [2] 69 02 [2] 75 2d }

  condition:
    any of them
}