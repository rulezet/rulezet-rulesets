rule TTP_XOR_QUAD_CurrentVersionRun_0ce2 {
  strings:
    $key_0ce2 = { 5f 8d [2] 7b 83 [2] 50 af [2] 7e 8d [2] 6a 96 [2] 65 8c [2] 7b 91 [2] 79 90 [2] 62 96 [2] 7e 91 [2] 62 be }

  condition:
    any of them
}