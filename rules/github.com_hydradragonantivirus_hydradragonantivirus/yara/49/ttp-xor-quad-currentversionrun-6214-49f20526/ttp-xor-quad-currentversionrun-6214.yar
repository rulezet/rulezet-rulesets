rule TTP_XOR_QUAD_CurrentVersionRun_6214 {
  strings:
    $key_6214 = { 31 7b [2] 15 75 [2] 3e 59 [2] 10 7b [2] 04 60 [2] 0b 7a [2] 15 67 [2] 17 66 [2] 0c 60 [2] 10 67 [2] 0c 48 }

  condition:
    any of them
}