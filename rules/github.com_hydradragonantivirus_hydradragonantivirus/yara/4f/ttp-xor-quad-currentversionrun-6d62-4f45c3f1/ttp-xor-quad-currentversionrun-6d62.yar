rule TTP_XOR_QUAD_CurrentVersionRun_6d62 {
  strings:
    $key_6d62 = { 3e 0d [2] 1a 03 [2] 31 2f [2] 1f 0d [2] 0b 16 [2] 04 0c [2] 1a 11 [2] 18 10 [2] 03 16 [2] 1f 11 [2] 03 3e }

  condition:
    any of them
}