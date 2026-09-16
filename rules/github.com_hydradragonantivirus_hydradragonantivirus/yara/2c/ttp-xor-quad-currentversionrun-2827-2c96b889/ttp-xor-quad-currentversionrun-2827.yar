rule TTP_XOR_QUAD_CurrentVersionRun_2827 {
  strings:
    $key_2827 = { 7b 48 [2] 5f 46 [2] 74 6a [2] 5a 48 [2] 4e 53 [2] 41 49 [2] 5f 54 [2] 5d 55 [2] 46 53 [2] 5a 54 [2] 46 7b }

  condition:
    any of them
}