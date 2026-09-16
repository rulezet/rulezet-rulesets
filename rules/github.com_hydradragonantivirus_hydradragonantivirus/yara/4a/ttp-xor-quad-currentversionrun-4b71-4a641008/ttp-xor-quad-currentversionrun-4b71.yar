rule TTP_XOR_QUAD_CurrentVersionRun_4b71 {
  strings:
    $key_4b71 = { 18 1e [2] 3c 10 [2] 17 3c [2] 39 1e [2] 2d 05 [2] 22 1f [2] 3c 02 [2] 3e 03 [2] 25 05 [2] 39 02 [2] 25 2d }

  condition:
    any of them
}