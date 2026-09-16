rule TTP_XOR_QUAD_CurrentVersionRun_3d41 {
  strings:
    $key_3d41 = { 6e 2e [2] 4a 20 [2] 61 0c [2] 4f 2e [2] 5b 35 [2] 54 2f [2] 4a 32 [2] 48 33 [2] 53 35 [2] 4f 32 [2] 53 1d }

  condition:
    any of them
}