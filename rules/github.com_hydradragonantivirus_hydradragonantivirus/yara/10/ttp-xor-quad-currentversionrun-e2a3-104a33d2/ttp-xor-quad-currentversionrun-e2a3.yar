rule TTP_XOR_QUAD_CurrentVersionRun_e2a3 {
  strings:
    $key_e2a3 = { b1 cc [2] 95 c2 [2] be ee [2] 90 cc [2] 84 d7 [2] 8b cd [2] 95 d0 [2] 97 d1 [2] 8c d7 [2] 90 d0 [2] 8c ff }

  condition:
    any of them
}