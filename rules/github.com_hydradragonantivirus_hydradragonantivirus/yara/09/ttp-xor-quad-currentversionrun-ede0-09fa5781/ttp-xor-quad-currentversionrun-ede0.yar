rule TTP_XOR_QUAD_CurrentVersionRun_ede0 {
  strings:
    $key_ede0 = { be 8f [2] 9a 81 [2] b1 ad [2] 9f 8f [2] 8b 94 [2] 84 8e [2] 9a 93 [2] 98 92 [2] 83 94 [2] 9f 93 [2] 83 bc }

  condition:
    any of them
}