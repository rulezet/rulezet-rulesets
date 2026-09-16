rule TTP_XOR_QUAD_CurrentVersionRun_6d40 {
  strings:
    $key_6d40 = { 3e 2f [2] 1a 21 [2] 31 0d [2] 1f 2f [2] 0b 34 [2] 04 2e [2] 1a 33 [2] 18 32 [2] 03 34 [2] 1f 33 [2] 03 1c }

  condition:
    any of them
}