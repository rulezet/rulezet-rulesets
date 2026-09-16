rule TTP_XOR_QUAD_CurrentVersionRun_ece2 {
  strings:
    $key_ece2 = { bf 8d [2] 9b 83 [2] b0 af [2] 9e 8d [2] 8a 96 [2] 85 8c [2] 9b 91 [2] 99 90 [2] 82 96 [2] 9e 91 [2] 82 be }

  condition:
    any of them
}