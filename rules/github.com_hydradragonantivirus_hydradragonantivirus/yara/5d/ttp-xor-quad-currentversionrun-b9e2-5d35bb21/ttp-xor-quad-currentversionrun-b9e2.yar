rule TTP_XOR_QUAD_CurrentVersionRun_b9e2 {
  strings:
    $key_b9e2 = { ea 8d [2] ce 83 [2] e5 af [2] cb 8d [2] df 96 [2] d0 8c [2] ce 91 [2] cc 90 [2] d7 96 [2] cb 91 [2] d7 be }

  condition:
    any of them
}