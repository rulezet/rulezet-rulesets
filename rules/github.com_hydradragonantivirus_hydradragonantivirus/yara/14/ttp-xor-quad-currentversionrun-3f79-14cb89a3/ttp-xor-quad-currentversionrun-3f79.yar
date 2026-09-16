rule TTP_XOR_QUAD_CurrentVersionRun_3f79 {
  strings:
    $key_3f79 = { 6c 16 [2] 48 18 [2] 63 34 [2] 4d 16 [2] 59 0d [2] 56 17 [2] 48 0a [2] 4a 0b [2] 51 0d [2] 4d 0a [2] 51 25 }

  condition:
    any of them
}