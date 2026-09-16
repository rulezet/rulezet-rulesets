rule TTP_XOR_QUAD_CurrentVersionRun_fadd {
  strings:
    $key_fadd = { a9 b2 [2] 8d bc [2] a6 90 [2] 88 b2 [2] 9c a9 [2] 93 b3 [2] 8d ae [2] 8f af [2] 94 a9 [2] 88 ae [2] 94 81 }

  condition:
    any of them
}