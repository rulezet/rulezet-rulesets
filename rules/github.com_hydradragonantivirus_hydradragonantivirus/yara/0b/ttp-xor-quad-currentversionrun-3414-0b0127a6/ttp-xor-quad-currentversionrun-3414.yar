rule TTP_XOR_QUAD_CurrentVersionRun_3414 {
  strings:
    $key_3414 = { 67 7b [2] 43 75 [2] 68 59 [2] 46 7b [2] 52 60 [2] 5d 7a [2] 43 67 [2] 41 66 [2] 5a 60 [2] 46 67 [2] 5a 48 }

  condition:
    any of them
}