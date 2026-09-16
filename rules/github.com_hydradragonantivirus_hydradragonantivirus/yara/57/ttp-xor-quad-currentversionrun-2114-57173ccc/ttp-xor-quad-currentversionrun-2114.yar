rule TTP_XOR_QUAD_CurrentVersionRun_2114 {
  strings:
    $key_2114 = { 72 7b [2] 56 75 [2] 7d 59 [2] 53 7b [2] 47 60 [2] 48 7a [2] 56 67 [2] 54 66 [2] 4f 60 [2] 53 67 [2] 4f 48 }

  condition:
    any of them
}