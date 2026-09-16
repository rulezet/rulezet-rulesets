rule TTP_XOR_QUAD_CurrentVersionRun_6c11 {
  strings:
    $key_6c11 = { 3f 7e [2] 1b 70 [2] 30 5c [2] 1e 7e [2] 0a 65 [2] 05 7f [2] 1b 62 [2] 19 63 [2] 02 65 [2] 1e 62 [2] 02 4d }

  condition:
    any of them
}