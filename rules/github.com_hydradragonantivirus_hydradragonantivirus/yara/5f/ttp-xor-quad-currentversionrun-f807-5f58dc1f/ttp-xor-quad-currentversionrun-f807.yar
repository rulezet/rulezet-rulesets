rule TTP_XOR_QUAD_CurrentVersionRun_f807 {
  strings:
    $key_f807 = { ab 68 [2] 8f 66 [2] a4 4a [2] 8a 68 [2] 9e 73 [2] 91 69 [2] 8f 74 [2] 8d 75 [2] 96 73 [2] 8a 74 [2] 96 5b }

  condition:
    any of them
}