rule TTP_XOR_QUAD_CurrentVersionRun_1478 {
  strings:
    $key_1478 = { 47 17 [2] 63 19 [2] 48 35 [2] 66 17 [2] 72 0c [2] 7d 16 [2] 63 0b [2] 61 0a [2] 7a 0c [2] 66 0b [2] 7a 24 }

  condition:
    any of them
}