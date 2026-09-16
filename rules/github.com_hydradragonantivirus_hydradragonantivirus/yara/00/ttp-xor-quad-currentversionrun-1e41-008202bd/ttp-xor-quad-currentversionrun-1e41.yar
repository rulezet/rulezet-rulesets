rule TTP_XOR_QUAD_CurrentVersionRun_1e41 {
  strings:
    $key_1e41 = { 4d 2e [2] 69 20 [2] 42 0c [2] 6c 2e [2] 78 35 [2] 77 2f [2] 69 32 [2] 6b 33 [2] 70 35 [2] 6c 32 [2] 70 1d }

  condition:
    any of them
}