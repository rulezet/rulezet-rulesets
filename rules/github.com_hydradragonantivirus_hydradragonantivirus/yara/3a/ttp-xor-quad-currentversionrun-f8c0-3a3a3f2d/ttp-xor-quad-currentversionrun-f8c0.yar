rule TTP_XOR_QUAD_CurrentVersionRun_f8c0 {
  strings:
    $key_f8c0 = { ab af [2] 8f a1 [2] a4 8d [2] 8a af [2] 9e b4 [2] 91 ae [2] 8f b3 [2] 8d b2 [2] 96 b4 [2] 8a b3 [2] 96 9c }

  condition:
    any of them
}