rule TTP_XOR_QUAD_CurrentVersionRun_e827 {
  strings:
    $key_e827 = { bb 48 [2] 9f 46 [2] b4 6a [2] 9a 48 [2] 8e 53 [2] 81 49 [2] 9f 54 [2] 9d 55 [2] 86 53 [2] 9a 54 [2] 86 7b }

  condition:
    any of them
}