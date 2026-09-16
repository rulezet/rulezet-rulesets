rule TTP_XOR_QUAD_CurrentVersionRun_dde0 {
  strings:
    $key_dde0 = { 8e 8f [2] aa 81 [2] 81 ad [2] af 8f [2] bb 94 [2] b4 8e [2] aa 93 [2] a8 92 [2] b3 94 [2] af 93 [2] b3 bc }

  condition:
    any of them
}