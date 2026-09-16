rule TTP_XOR_QUAD_CurrentVersionRun_3a34 {
  strings:
    $key_3a34 = { 69 5b [2] 4d 55 [2] 66 79 [2] 48 5b [2] 5c 40 [2] 53 5a [2] 4d 47 [2] 4f 46 [2] 54 40 [2] 48 47 [2] 54 68 }

  condition:
    any of them
}