rule TTP_XOR_QUAD_CurrentVersionRun_e811 {
  strings:
    $key_e811 = { bb 7e [2] 9f 70 [2] b4 5c [2] 9a 7e [2] 8e 65 [2] 81 7f [2] 9f 62 [2] 9d 63 [2] 86 65 [2] 9a 62 [2] 86 4d }

  condition:
    any of them
}