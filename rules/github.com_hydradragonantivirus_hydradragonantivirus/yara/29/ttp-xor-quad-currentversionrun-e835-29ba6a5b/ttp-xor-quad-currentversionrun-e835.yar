rule TTP_XOR_QUAD_CurrentVersionRun_e835 {
  strings:
    $key_e835 = { bb 5a [2] 9f 54 [2] b4 78 [2] 9a 5a [2] 8e 41 [2] 81 5b [2] 9f 46 [2] 9d 47 [2] 86 41 [2] 9a 46 [2] 86 69 }

  condition:
    any of them
}