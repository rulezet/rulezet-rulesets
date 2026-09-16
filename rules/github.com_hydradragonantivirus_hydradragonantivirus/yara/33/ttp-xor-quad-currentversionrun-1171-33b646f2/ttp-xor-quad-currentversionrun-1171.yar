rule TTP_XOR_QUAD_CurrentVersionRun_1171 {
  strings:
    $key_1171 = { 42 1e [2] 66 10 [2] 4d 3c [2] 63 1e [2] 77 05 [2] 78 1f [2] 66 02 [2] 64 03 [2] 7f 05 [2] 63 02 [2] 7f 2d }

  condition:
    any of them
}