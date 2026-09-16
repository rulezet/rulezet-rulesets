rule TTP_XOR_QUAD_CurrentVersionRun_0df1 {
  strings:
    $key_0df1 = { 5e 9e [2] 7a 90 [2] 51 bc [2] 7f 9e [2] 6b 85 [2] 64 9f [2] 7a 82 [2] 78 83 [2] 63 85 [2] 7f 82 [2] 63 ad }

  condition:
    any of them
}