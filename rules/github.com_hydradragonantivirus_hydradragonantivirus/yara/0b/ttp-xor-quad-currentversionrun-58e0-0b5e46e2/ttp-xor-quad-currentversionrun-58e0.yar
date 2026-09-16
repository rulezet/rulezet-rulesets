rule TTP_XOR_QUAD_CurrentVersionRun_58e0 {
  strings:
    $key_58e0 = { 0b 8f [2] 2f 81 [2] 04 ad [2] 2a 8f [2] 3e 94 [2] 31 8e [2] 2f 93 [2] 2d 92 [2] 36 94 [2] 2a 93 [2] 36 bc }

  condition:
    any of them
}