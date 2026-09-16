rule TTP_XOR_QUAD_CurrentVersionRun_7e28 {
  strings:
    $key_7e28 = { 2d 47 [2] 09 49 [2] 22 65 [2] 0c 47 [2] 18 5c [2] 17 46 [2] 09 5b [2] 0b 5a [2] 10 5c [2] 0c 5b [2] 10 74 }

  condition:
    any of them
}