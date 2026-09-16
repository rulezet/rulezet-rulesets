rule TTP_XOR_QUAD_CurrentVersionRun_fcf1 {
  strings:
    $key_fcf1 = { af 9e [2] 8b 90 [2] a0 bc [2] 8e 9e [2] 9a 85 [2] 95 9f [2] 8b 82 [2] 89 83 [2] 92 85 [2] 8e 82 [2] 92 ad }

  condition:
    any of them
}