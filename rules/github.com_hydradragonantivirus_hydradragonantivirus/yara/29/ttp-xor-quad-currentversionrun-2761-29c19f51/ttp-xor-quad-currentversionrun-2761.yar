rule TTP_XOR_QUAD_CurrentVersionRun_2761 {
  strings:
    $key_2761 = { 74 0e [2] 50 00 [2] 7b 2c [2] 55 0e [2] 41 15 [2] 4e 0f [2] 50 12 [2] 52 13 [2] 49 15 [2] 55 12 [2] 49 3d }

  condition:
    any of them
}