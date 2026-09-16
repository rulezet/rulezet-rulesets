rule TTP_XOR_QUAD_CurrentVersionRun_e8dd {
  strings:
    $key_e8dd = { bb b2 [2] 9f bc [2] b4 90 [2] 9a b2 [2] 8e a9 [2] 81 b3 [2] 9f ae [2] 9d af [2] 86 a9 [2] 9a ae [2] 86 81 }

  condition:
    any of them
}