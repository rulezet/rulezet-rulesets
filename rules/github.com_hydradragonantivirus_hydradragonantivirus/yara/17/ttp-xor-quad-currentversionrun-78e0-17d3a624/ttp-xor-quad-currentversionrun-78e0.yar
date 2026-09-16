rule TTP_XOR_QUAD_CurrentVersionRun_78e0 {
  strings:
    $key_78e0 = { 2b 8f [2] 0f 81 [2] 24 ad [2] 0a 8f [2] 1e 94 [2] 11 8e [2] 0f 93 [2] 0d 92 [2] 16 94 [2] 0a 93 [2] 16 bc }

  condition:
    any of them
}