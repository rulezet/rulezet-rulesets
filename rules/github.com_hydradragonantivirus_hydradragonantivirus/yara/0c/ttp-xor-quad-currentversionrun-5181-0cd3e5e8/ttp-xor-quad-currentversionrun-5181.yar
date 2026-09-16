rule TTP_XOR_QUAD_CurrentVersionRun_5181 {
  strings:
    $key_5181 = { 02 ee [2] 26 e0 [2] 0d cc [2] 23 ee [2] 37 f5 [2] 38 ef [2] 26 f2 [2] 24 f3 [2] 3f f5 [2] 23 f2 [2] 3f dd }

  condition:
    any of them
}