rule TTP_XOR_QUAD_CurrentVersionRun_fdc1 {
  strings:
    $key_fdc1 = { ae ae [2] 8a a0 [2] a1 8c [2] 8f ae [2] 9b b5 [2] 94 af [2] 8a b2 [2] 88 b3 [2] 93 b5 [2] 8f b2 [2] 93 9d }

  condition:
    any of them
}