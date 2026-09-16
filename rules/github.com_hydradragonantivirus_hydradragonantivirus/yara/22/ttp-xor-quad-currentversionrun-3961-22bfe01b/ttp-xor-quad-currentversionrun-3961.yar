rule TTP_XOR_QUAD_CurrentVersionRun_3961 {
  strings:
    $key_3961 = { 6a 0e [2] 4e 00 [2] 65 2c [2] 4b 0e [2] 5f 15 [2] 50 0f [2] 4e 12 [2] 4c 13 [2] 57 15 [2] 4b 12 [2] 57 3d }

  condition:
    any of them
}