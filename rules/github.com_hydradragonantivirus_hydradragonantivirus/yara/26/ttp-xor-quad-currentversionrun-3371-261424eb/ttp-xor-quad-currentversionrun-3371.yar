rule TTP_XOR_QUAD_CurrentVersionRun_3371 {
  strings:
    $key_3371 = { 60 1e [2] 44 10 [2] 6f 3c [2] 41 1e [2] 55 05 [2] 5a 1f [2] 44 02 [2] 46 03 [2] 5d 05 [2] 41 02 [2] 5d 2d }

  condition:
    any of them
}