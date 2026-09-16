rule TTP_XOR_QUAD_CurrentVersionRun_3365 {
  strings:
    $key_3365 = { 60 0a [2] 44 04 [2] 6f 28 [2] 41 0a [2] 55 11 [2] 5a 0b [2] 44 16 [2] 46 17 [2] 5d 11 [2] 41 16 [2] 5d 39 }

  condition:
    any of them
}