rule TTP_XOR_QUAD_CurrentVersionRun_2b71 {
  strings:
    $key_2b71 = { 78 1e [2] 5c 10 [2] 77 3c [2] 59 1e [2] 4d 05 [2] 42 1f [2] 5c 02 [2] 5e 03 [2] 45 05 [2] 59 02 [2] 45 2d }

  condition:
    any of them
}