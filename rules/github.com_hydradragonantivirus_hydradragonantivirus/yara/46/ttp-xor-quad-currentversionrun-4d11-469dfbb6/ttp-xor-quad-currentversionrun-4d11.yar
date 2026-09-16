rule TTP_XOR_QUAD_CurrentVersionRun_4d11 {
  strings:
    $key_4d11 = { 1e 7e [2] 3a 70 [2] 11 5c [2] 3f 7e [2] 2b 65 [2] 24 7f [2] 3a 62 [2] 38 63 [2] 23 65 [2] 3f 62 [2] 23 4d }

  condition:
    any of them
}