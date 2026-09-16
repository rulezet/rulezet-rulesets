rule TTP_XOR_QUAD_CurrentVersionRun_3b14 {
  strings:
    $key_3b14 = { 68 7b [2] 4c 75 [2] 67 59 [2] 49 7b [2] 5d 60 [2] 52 7a [2] 4c 67 [2] 4e 66 [2] 55 60 [2] 49 67 [2] 55 48 }

  condition:
    any of them
}