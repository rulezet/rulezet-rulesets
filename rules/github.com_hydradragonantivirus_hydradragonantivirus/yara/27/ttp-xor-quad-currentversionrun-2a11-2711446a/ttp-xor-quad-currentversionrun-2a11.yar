rule TTP_XOR_QUAD_CurrentVersionRun_2a11 {
  strings:
    $key_2a11 = { 79 7e [2] 5d 70 [2] 76 5c [2] 58 7e [2] 4c 65 [2] 43 7f [2] 5d 62 [2] 5f 63 [2] 44 65 [2] 58 62 [2] 44 4d }

  condition:
    any of them
}