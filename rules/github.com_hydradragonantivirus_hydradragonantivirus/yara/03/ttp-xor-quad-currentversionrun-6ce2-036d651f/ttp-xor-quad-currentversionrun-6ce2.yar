rule TTP_XOR_QUAD_CurrentVersionRun_6ce2 {
  strings:
    $key_6ce2 = { 3f 8d [2] 1b 83 [2] 30 af [2] 1e 8d [2] 0a 96 [2] 05 8c [2] 1b 91 [2] 19 90 [2] 02 96 [2] 1e 91 [2] 02 be }

  condition:
    any of them
}