rule TTP_XOR_QUAD_CurrentVersionRun_fdc0 {
  strings:
    $key_fdc0 = { ae af [2] 8a a1 [2] a1 8d [2] 8f af [2] 9b b4 [2] 94 ae [2] 8a b3 [2] 88 b2 [2] 93 b4 [2] 8f b3 [2] 93 9c }

  condition:
    any of them
}