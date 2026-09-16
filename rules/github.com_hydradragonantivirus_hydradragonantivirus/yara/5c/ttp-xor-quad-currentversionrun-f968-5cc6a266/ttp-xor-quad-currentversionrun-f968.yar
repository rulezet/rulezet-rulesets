rule TTP_XOR_QUAD_CurrentVersionRun_f968 {
  strings:
    $key_f968 = { aa 07 [2] 8e 09 [2] a5 25 [2] 8b 07 [2] 9f 1c [2] 90 06 [2] 8e 1b [2] 8c 1a [2] 97 1c [2] 8b 1b [2] 97 34 }

  condition:
    any of them
}