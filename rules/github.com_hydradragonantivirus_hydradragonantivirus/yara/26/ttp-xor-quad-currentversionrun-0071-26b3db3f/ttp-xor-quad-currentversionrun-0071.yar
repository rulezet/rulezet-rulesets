rule TTP_XOR_QUAD_CurrentVersionRun_0071 {
  strings:
    $key_0071 = { 53 1e [2] 77 10 [2] 5c 3c [2] 72 1e [2] 66 05 [2] 69 1f [2] 77 02 [2] 75 03 [2] 6e 05 [2] 72 02 [2] 6e 2d }

  condition:
    any of them
}