rule TTP_XOR_QUAD_CurrentVersionRun_3b71 {
  strings:
    $key_3b71 = { 68 1e [2] 4c 10 [2] 67 3c [2] 49 1e [2] 5d 05 [2] 52 1f [2] 4c 02 [2] 4e 03 [2] 55 05 [2] 49 02 [2] 55 2d }

  condition:
    any of them
}