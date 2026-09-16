rule TTP_XOR_QUAD_CurrentVersionRun_1259 {
  strings:
    $key_1259 = { 41 36 [2] 65 38 [2] 4e 14 [2] 60 36 [2] 74 2d [2] 7b 37 [2] 65 2a [2] 67 2b [2] 7c 2d [2] 60 2a [2] 7c 05 }

  condition:
    any of them
}