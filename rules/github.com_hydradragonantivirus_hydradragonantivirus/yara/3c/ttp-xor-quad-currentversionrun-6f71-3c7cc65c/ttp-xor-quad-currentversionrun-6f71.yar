rule TTP_XOR_QUAD_CurrentVersionRun_6f71 {
  strings:
    $key_6f71 = { 3c 1e [2] 18 10 [2] 33 3c [2] 1d 1e [2] 09 05 [2] 06 1f [2] 18 02 [2] 1a 03 [2] 01 05 [2] 1d 02 [2] 01 2d }

  condition:
    any of them
}