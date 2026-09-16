rule TTP_XOR_QUAD_CurrentVersionRun_e8eb {
  strings:
    $key_e8eb = { bb 84 [2] 9f 8a [2] b4 a6 [2] 9a 84 [2] 8e 9f [2] 81 85 [2] 9f 98 [2] 9d 99 [2] 86 9f [2] 9a 98 [2] 86 b7 }

  condition:
    any of them
}