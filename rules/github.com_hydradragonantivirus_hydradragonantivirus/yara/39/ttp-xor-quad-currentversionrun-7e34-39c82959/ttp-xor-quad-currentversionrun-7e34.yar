rule TTP_XOR_QUAD_CurrentVersionRun_7e34 {
  strings:
    $key_7e34 = { 2d 5b [2] 09 55 [2] 22 79 [2] 0c 5b [2] 18 40 [2] 17 5a [2] 09 47 [2] 0b 46 [2] 10 40 [2] 0c 47 [2] 10 68 }

  condition:
    any of them
}