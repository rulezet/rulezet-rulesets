rule TTP_XOR_QUAD_CurrentVersionRun_6d63 {
  strings:
    $key_6d63 = { 3e 0c [2] 1a 02 [2] 31 2e [2] 1f 0c [2] 0b 17 [2] 04 0d [2] 1a 10 [2] 18 11 [2] 03 17 [2] 1f 10 [2] 03 3f }

  condition:
    any of them
}