rule TTP_XOR_QUAD_CurrentVersionRun_6263 {
  strings:
    $key_6263 = { 31 0c [2] 15 02 [2] 3e 2e [2] 10 0c [2] 04 17 [2] 0b 0d [2] 15 10 [2] 17 11 [2] 0c 17 [2] 10 10 [2] 0c 3f }

  condition:
    any of them
}