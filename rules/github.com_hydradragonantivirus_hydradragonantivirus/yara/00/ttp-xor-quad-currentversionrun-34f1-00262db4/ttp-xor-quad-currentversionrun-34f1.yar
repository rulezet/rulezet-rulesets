rule TTP_XOR_QUAD_CurrentVersionRun_34f1 {
  strings:
    $key_34f1 = { 67 9e [2] 43 90 [2] 68 bc [2] 46 9e [2] 52 85 [2] 5d 9f [2] 43 82 [2] 41 83 [2] 5a 85 [2] 46 82 [2] 5a ad }

  condition:
    any of them
}