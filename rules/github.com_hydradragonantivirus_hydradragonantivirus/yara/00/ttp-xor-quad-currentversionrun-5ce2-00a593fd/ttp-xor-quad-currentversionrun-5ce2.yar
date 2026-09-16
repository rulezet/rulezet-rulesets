rule TTP_XOR_QUAD_CurrentVersionRun_5ce2 {
  strings:
    $key_5ce2 = { 0f 8d [2] 2b 83 [2] 00 af [2] 2e 8d [2] 3a 96 [2] 35 8c [2] 2b 91 [2] 29 90 [2] 32 96 [2] 2e 91 [2] 32 be }

  condition:
    any of them
}