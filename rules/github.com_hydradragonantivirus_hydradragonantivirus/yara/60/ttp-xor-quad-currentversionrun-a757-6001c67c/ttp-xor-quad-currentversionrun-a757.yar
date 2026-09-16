rule TTP_XOR_QUAD_CurrentVersionRun_a757 {
  strings:
    $key_a757 = { f4 38 [2] d0 36 [2] fb 1a [2] d5 38 [2] c1 23 [2] ce 39 [2] d0 24 [2] d2 25 [2] c9 23 [2] d5 24 [2] c9 0b }

  condition:
    any of them
}