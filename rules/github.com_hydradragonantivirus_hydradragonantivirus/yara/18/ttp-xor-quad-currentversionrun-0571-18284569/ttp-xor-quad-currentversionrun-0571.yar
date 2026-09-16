rule TTP_XOR_QUAD_CurrentVersionRun_0571 {
  strings:
    $key_0571 = { 56 1e [2] 72 10 [2] 59 3c [2] 77 1e [2] 63 05 [2] 6c 1f [2] 72 02 [2] 70 03 [2] 6b 05 [2] 77 02 [2] 6b 2d }

  condition:
    any of them
}