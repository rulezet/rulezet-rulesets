rule TTP_XOR_QUAD_CurrentVersionRun_bfdb {
  strings:
    $key_bfdb = { ec b4 [2] c8 ba [2] e3 96 [2] cd b4 [2] d9 af [2] d6 b5 [2] c8 a8 [2] ca a9 [2] d1 af [2] cd a8 [2] d1 87 }

  condition:
    any of them
}