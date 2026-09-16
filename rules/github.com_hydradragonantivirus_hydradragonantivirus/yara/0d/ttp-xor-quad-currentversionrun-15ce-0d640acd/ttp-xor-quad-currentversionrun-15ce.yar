rule TTP_XOR_QUAD_CurrentVersionRun_15ce {
  strings:
    $key_15ce = { 46 a1 [2] 62 af [2] 49 83 [2] 67 a1 [2] 73 ba [2] 7c a0 [2] 62 bd [2] 60 bc [2] 7b ba [2] 67 bd [2] 7b 92 }

  condition:
    any of them
}