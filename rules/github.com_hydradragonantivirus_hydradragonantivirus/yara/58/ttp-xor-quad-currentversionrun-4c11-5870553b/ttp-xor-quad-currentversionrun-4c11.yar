rule TTP_XOR_QUAD_CurrentVersionRun_4c11 {
  strings:
    $key_4c11 = { 1f 7e [2] 3b 70 [2] 10 5c [2] 3e 7e [2] 2a 65 [2] 25 7f [2] 3b 62 [2] 39 63 [2] 22 65 [2] 3e 62 [2] 22 4d }

  condition:
    any of them
}