rule TTP_XOR_QUAD_CurrentVersionRun_0b11 {
  strings:
    $key_0b11 = { 58 7e [2] 7c 70 [2] 57 5c [2] 79 7e [2] 6d 65 [2] 62 7f [2] 7c 62 [2] 7e 63 [2] 65 65 [2] 79 62 [2] 65 4d }

  condition:
    any of them
}