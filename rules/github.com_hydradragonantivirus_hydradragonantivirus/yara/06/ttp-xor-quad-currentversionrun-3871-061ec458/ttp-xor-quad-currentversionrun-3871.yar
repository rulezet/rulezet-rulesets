rule TTP_XOR_QUAD_CurrentVersionRun_3871 {
  strings:
    $key_3871 = { 6b 1e [2] 4f 10 [2] 64 3c [2] 4a 1e [2] 5e 05 [2] 51 1f [2] 4f 02 [2] 4d 03 [2] 56 05 [2] 4a 02 [2] 56 2d }

  condition:
    any of them
}