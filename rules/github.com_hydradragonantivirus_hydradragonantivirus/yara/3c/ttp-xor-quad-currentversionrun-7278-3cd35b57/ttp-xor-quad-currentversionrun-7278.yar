rule TTP_XOR_QUAD_CurrentVersionRun_7278 {
  strings:
    $key_7278 = { 21 17 [2] 05 19 [2] 2e 35 [2] 00 17 [2] 14 0c [2] 1b 16 [2] 05 0b [2] 07 0a [2] 1c 0c [2] 00 0b [2] 1c 24 }

  condition:
    any of them
}