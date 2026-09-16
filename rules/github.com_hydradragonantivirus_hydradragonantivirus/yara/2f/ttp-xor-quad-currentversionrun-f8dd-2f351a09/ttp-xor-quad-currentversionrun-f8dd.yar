rule TTP_XOR_QUAD_CurrentVersionRun_f8dd {
  strings:
    $key_f8dd = { ab b2 [2] 8f bc [2] a4 90 [2] 8a b2 [2] 9e a9 [2] 91 b3 [2] 8f ae [2] 8d af [2] 96 a9 [2] 8a ae [2] 96 81 }

  condition:
    any of them
}