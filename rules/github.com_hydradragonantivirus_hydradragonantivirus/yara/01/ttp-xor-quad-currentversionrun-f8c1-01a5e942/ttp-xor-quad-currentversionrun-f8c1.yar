rule TTP_XOR_QUAD_CurrentVersionRun_f8c1 {
  strings:
    $key_f8c1 = { ab ae [2] 8f a0 [2] a4 8c [2] 8a ae [2] 9e b5 [2] 91 af [2] 8f b2 [2] 8d b3 [2] 96 b5 [2] 8a b2 [2] 96 9d }

  condition:
    any of them
}