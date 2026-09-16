rule TTP_XOR_QUAD_CurrentVersionRun_eaf4 {
  strings:
    $key_eaf4 = { b9 9b [2] 9d 95 [2] b6 b9 [2] 98 9b [2] 8c 80 [2] 83 9a [2] 9d 87 [2] 9f 86 [2] 84 80 [2] 98 87 [2] 84 a8 }

  condition:
    any of them
}