rule TTP_XOR_QUAD_CurrentVersionRun_1314 {
  strings:
    $key_1314 = { 40 7b [2] 64 75 [2] 4f 59 [2] 61 7b [2] 75 60 [2] 7a 7a [2] 64 67 [2] 66 66 [2] 7d 60 [2] 61 67 [2] 7d 48 }

  condition:
    any of them
}