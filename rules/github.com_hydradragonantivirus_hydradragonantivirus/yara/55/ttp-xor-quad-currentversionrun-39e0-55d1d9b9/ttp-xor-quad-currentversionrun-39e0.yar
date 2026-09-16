rule TTP_XOR_QUAD_CurrentVersionRun_39e0 {
  strings:
    $key_39e0 = { 6a 8f [2] 4e 81 [2] 65 ad [2] 4b 8f [2] 5f 94 [2] 50 8e [2] 4e 93 [2] 4c 92 [2] 57 94 [2] 4b 93 [2] 57 bc }

  condition:
    any of them
}