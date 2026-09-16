rule TTP_XOR_QUAD_CurrentVersionRun_14f1 {
  strings:
    $key_14f1 = { 47 9e [2] 63 90 [2] 48 bc [2] 66 9e [2] 72 85 [2] 7d 9f [2] 63 82 [2] 61 83 [2] 7a 85 [2] 66 82 [2] 7a ad }

  condition:
    any of them
}