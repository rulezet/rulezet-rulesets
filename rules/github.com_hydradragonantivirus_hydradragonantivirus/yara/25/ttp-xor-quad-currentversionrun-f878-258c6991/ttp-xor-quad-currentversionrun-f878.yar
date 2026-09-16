rule TTP_XOR_QUAD_CurrentVersionRun_f878 {
  strings:
    $key_f878 = { ab 17 [2] 8f 19 [2] a4 35 [2] 8a 17 [2] 9e 0c [2] 91 16 [2] 8f 0b [2] 8d 0a [2] 96 0c [2] 8a 0b [2] 96 24 }

  condition:
    any of them
}