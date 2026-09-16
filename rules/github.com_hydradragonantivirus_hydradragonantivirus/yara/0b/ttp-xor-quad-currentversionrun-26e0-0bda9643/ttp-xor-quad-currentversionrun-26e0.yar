rule TTP_XOR_QUAD_CurrentVersionRun_26e0 {
  strings:
    $key_26e0 = { 75 8f [2] 51 81 [2] 7a ad [2] 54 8f [2] 40 94 [2] 4f 8e [2] 51 93 [2] 53 92 [2] 48 94 [2] 54 93 [2] 48 bc }

  condition:
    any of them
}