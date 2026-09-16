rule TTP_XOR_QUAD_CurrentVersionRun_7f34 {
  strings:
    $key_7f34 = { 2c 5b [2] 08 55 [2] 23 79 [2] 0d 5b [2] 19 40 [2] 16 5a [2] 08 47 [2] 0a 46 [2] 11 40 [2] 0d 47 [2] 11 68 }

  condition:
    any of them
}