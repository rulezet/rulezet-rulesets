rule TTP_XOR_QUAD_CurrentVersionRun_0541 {
  strings:
    $key_0541 = { 56 2e [2] 72 20 [2] 59 0c [2] 77 2e [2] 63 35 [2] 6c 2f [2] 72 32 [2] 70 33 [2] 6b 35 [2] 77 32 [2] 6b 1d }

  condition:
    any of them
}