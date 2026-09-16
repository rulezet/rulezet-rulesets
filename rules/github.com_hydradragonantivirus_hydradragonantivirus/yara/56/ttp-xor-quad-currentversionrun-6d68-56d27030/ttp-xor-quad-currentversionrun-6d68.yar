rule TTP_XOR_QUAD_CurrentVersionRun_6d68 {
  strings:
    $key_6d68 = { 3e 07 [2] 1a 09 [2] 31 25 [2] 1f 07 [2] 0b 1c [2] 04 06 [2] 1a 1b [2] 18 1a [2] 03 1c [2] 1f 1b [2] 03 34 }

  condition:
    any of them
}