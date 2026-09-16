rule TTP_XOR_QUAD_CurrentVersionRun_e735 {
  strings:
    $key_e735 = { b4 5a [2] 90 54 [2] bb 78 [2] 95 5a [2] 81 41 [2] 8e 5b [2] 90 46 [2] 92 47 [2] 89 41 [2] 95 46 [2] 89 69 }

  condition:
    any of them
}