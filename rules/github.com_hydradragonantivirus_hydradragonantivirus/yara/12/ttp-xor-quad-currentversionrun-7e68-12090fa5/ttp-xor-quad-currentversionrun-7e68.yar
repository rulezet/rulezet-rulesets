rule TTP_XOR_QUAD_CurrentVersionRun_7e68 {
  strings:
    $key_7e68 = { 2d 07 [2] 09 09 [2] 22 25 [2] 0c 07 [2] 18 1c [2] 17 06 [2] 09 1b [2] 0b 1a [2] 10 1c [2] 0c 1b [2] 10 34 }

  condition:
    any of them
}