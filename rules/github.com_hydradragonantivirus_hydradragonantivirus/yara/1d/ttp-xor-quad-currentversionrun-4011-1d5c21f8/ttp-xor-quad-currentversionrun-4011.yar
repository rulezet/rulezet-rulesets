rule TTP_XOR_QUAD_CurrentVersionRun_4011 {
  strings:
    $key_4011 = { 13 7e [2] 37 70 [2] 1c 5c [2] 32 7e [2] 26 65 [2] 29 7f [2] 37 62 [2] 35 63 [2] 2e 65 [2] 32 62 [2] 2e 4d }

  condition:
    any of them
}