rule TTP_XOR_QUAD_CurrentVersionRun_c5e0 {
  strings:
    $key_c5e0 = { 96 8f [2] b2 81 [2] 99 ad [2] b7 8f [2] a3 94 [2] ac 8e [2] b2 93 [2] b0 92 [2] ab 94 [2] b7 93 [2] ab bc }

  condition:
    any of them
}