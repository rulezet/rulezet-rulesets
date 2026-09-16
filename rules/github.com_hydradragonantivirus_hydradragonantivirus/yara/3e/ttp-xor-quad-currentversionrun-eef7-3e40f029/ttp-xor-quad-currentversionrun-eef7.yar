rule TTP_XOR_QUAD_CurrentVersionRun_eef7 {
  strings:
    $key_eef7 = { bd 98 [2] 99 96 [2] b2 ba [2] 9c 98 [2] 88 83 [2] 87 99 [2] 99 84 [2] 9b 85 [2] 80 83 [2] 9c 84 [2] 80 ab }

  condition:
    any of them
}