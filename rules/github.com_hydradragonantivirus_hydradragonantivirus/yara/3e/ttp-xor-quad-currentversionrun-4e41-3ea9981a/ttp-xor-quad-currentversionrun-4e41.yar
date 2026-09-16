rule TTP_XOR_QUAD_CurrentVersionRun_4e41 {
  strings:
    $key_4e41 = { 1d 2e [2] 39 20 [2] 12 0c [2] 3c 2e [2] 28 35 [2] 27 2f [2] 39 32 [2] 3b 33 [2] 20 35 [2] 3c 32 [2] 20 1d }

  condition:
    any of them
}