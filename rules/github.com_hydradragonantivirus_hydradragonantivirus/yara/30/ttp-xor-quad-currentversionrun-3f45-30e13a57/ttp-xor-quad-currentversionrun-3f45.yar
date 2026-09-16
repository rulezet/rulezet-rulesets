rule TTP_XOR_QUAD_CurrentVersionRun_3f45 {
  strings:
    $key_3f45 = { 6c 2a [2] 48 24 [2] 63 08 [2] 4d 2a [2] 59 31 [2] 56 2b [2] 48 36 [2] 4a 37 [2] 51 31 [2] 4d 36 [2] 51 19 }

  condition:
    any of them
}