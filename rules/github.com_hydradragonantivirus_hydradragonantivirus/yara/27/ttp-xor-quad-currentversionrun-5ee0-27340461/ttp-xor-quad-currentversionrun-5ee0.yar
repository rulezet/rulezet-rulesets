rule TTP_XOR_QUAD_CurrentVersionRun_5ee0 {
  strings:
    $key_5ee0 = { 0d 8f [2] 29 81 [2] 02 ad [2] 2c 8f [2] 38 94 [2] 37 8e [2] 29 93 [2] 2b 92 [2] 30 94 [2] 2c 93 [2] 30 bc }

  condition:
    any of them
}