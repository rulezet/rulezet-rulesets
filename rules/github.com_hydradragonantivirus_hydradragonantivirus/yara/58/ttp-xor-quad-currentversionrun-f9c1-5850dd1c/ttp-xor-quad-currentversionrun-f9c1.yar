rule TTP_XOR_QUAD_CurrentVersionRun_f9c1 {
  strings:
    $key_f9c1 = { aa ae [2] 8e a0 [2] a5 8c [2] 8b ae [2] 9f b5 [2] 90 af [2] 8e b2 [2] 8c b3 [2] 97 b5 [2] 8b b2 [2] 97 9d }

  condition:
    any of them
}