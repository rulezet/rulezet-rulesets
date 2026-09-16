rule TTP_XOR_QUAD_CurrentVersionRun_ee42 {
  strings:
    $key_ee42 = { bd 2d [2] 99 23 [2] b2 0f [2] 9c 2d [2] 88 36 [2] 87 2c [2] 99 31 [2] 9b 30 [2] 80 36 [2] 9c 31 [2] 80 1e }

  condition:
    any of them
}