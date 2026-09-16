rule TTP_XOR_QUAD_CurrentVersionRun_5d11 {
  strings:
    $key_5d11 = { 0e 7e [2] 2a 70 [2] 01 5c [2] 2f 7e [2] 3b 65 [2] 34 7f [2] 2a 62 [2] 28 63 [2] 33 65 [2] 2f 62 [2] 33 4d }

  condition:
    any of them
}