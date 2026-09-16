rule TTP_XOR_QUAD_CurrentVersionRun_3e34 {
  strings:
    $key_3e34 = { 6d 5b [2] 49 55 [2] 62 79 [2] 4c 5b [2] 58 40 [2] 57 5a [2] 49 47 [2] 4b 46 [2] 50 40 [2] 4c 47 [2] 50 68 }

  condition:
    any of them
}