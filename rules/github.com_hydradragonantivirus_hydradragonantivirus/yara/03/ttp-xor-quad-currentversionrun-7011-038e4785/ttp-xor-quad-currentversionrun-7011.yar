rule TTP_XOR_QUAD_CurrentVersionRun_7011 {
  strings:
    $key_7011 = { 23 7e [2] 07 70 [2] 2c 5c [2] 02 7e [2] 16 65 [2] 19 7f [2] 07 62 [2] 05 63 [2] 1e 65 [2] 02 62 [2] 1e 4d }

  condition:
    any of them
}