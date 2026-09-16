rule TTP_XOR_QUAD_CurrentVersionRun_1c11 {
  strings:
    $key_1c11 = { 4f 7e [2] 6b 70 [2] 40 5c [2] 6e 7e [2] 7a 65 [2] 75 7f [2] 6b 62 [2] 69 63 [2] 72 65 [2] 6e 62 [2] 72 4d }

  condition:
    any of them
}