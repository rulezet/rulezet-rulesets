rule TTP_XOR_QUAD_CurrentVersionRun_07e0 {
  strings:
    $key_07e0 = { 54 8f [2] 70 81 [2] 5b ad [2] 75 8f [2] 61 94 [2] 6e 8e [2] 70 93 [2] 72 92 [2] 69 94 [2] 75 93 [2] 69 bc }

  condition:
    any of them
}