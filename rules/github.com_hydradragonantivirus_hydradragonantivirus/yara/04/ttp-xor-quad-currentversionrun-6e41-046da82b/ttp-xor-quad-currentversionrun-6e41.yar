rule TTP_XOR_QUAD_CurrentVersionRun_6e41 {
  strings:
    $key_6e41 = { 3d 2e [2] 19 20 [2] 32 0c [2] 1c 2e [2] 08 35 [2] 07 2f [2] 19 32 [2] 1b 33 [2] 00 35 [2] 1c 32 [2] 00 1d }

  condition:
    any of them
}