rule TTP_XOR_QUAD_CurrentVersionRun_0271 {
  strings:
    $key_0271 = { 51 1e [2] 75 10 [2] 5e 3c [2] 70 1e [2] 64 05 [2] 6b 1f [2] 75 02 [2] 77 03 [2] 6c 05 [2] 70 02 [2] 6c 2d }

  condition:
    any of them
}