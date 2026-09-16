rule TTP_XOR_QUAD_CurrentVersionRun_4b34 {
  strings:
    $key_4b34 = { 18 5b [2] 3c 55 [2] 17 79 [2] 39 5b [2] 2d 40 [2] 22 5a [2] 3c 47 [2] 3e 46 [2] 25 40 [2] 39 47 [2] 25 68 }

  condition:
    any of them
}