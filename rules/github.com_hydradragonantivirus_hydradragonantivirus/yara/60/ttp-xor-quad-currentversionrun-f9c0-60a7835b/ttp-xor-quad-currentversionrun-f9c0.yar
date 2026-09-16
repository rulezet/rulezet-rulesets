rule TTP_XOR_QUAD_CurrentVersionRun_f9c0 {
  strings:
    $key_f9c0 = { aa af [2] 8e a1 [2] a5 8d [2] 8b af [2] 9f b4 [2] 90 ae [2] 8e b3 [2] 8c b2 [2] 97 b4 [2] 8b b3 [2] 97 9c }

  condition:
    any of them
}