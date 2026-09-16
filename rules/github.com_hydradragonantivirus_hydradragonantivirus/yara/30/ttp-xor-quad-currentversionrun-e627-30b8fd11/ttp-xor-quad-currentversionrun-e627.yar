rule TTP_XOR_QUAD_CurrentVersionRun_e627 {
  strings:
    $key_e627 = { b5 48 [2] 91 46 [2] ba 6a [2] 94 48 [2] 80 53 [2] 8f 49 [2] 91 54 [2] 93 55 [2] 88 53 [2] 94 54 [2] 88 7b }

  condition:
    any of them
}