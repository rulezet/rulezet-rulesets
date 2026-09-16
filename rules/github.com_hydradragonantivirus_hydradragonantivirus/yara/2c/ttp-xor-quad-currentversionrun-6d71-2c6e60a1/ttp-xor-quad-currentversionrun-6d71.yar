rule TTP_XOR_QUAD_CurrentVersionRun_6d71 {
  strings:
    $key_6d71 = { 3e 1e [2] 1a 10 [2] 31 3c [2] 1f 1e [2] 0b 05 [2] 04 1f [2] 1a 02 [2] 18 03 [2] 03 05 [2] 1f 02 [2] 03 2d }

  condition:
    any of them
}