rule TTP_XOR_QUAD_CurrentVersionRun_6d50 {
  strings:
    $key_6d50 = { 3e 3f [2] 1a 31 [2] 31 1d [2] 1f 3f [2] 0b 24 [2] 04 3e [2] 1a 23 [2] 18 22 [2] 03 24 [2] 1f 23 [2] 03 0c }

  condition:
    any of them
}