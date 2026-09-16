rule TTP_XOR_QUAD_CurrentVersionRun_2271 {
  strings:
    $key_2271 = { 71 1e [2] 55 10 [2] 7e 3c [2] 50 1e [2] 44 05 [2] 4b 1f [2] 55 02 [2] 57 03 [2] 4c 05 [2] 50 02 [2] 4c 2d }

  condition:
    any of them
}