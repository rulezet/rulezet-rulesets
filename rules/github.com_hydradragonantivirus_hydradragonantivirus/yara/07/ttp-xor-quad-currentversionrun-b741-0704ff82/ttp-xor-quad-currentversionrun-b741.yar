rule TTP_XOR_QUAD_CurrentVersionRun_b741 {
  strings:
    $key_b741 = { e4 2e [2] c0 20 [2] eb 0c [2] c5 2e [2] d1 35 [2] de 2f [2] c0 32 [2] c2 33 [2] d9 35 [2] c5 32 [2] d9 1d }

  condition:
    any of them
}