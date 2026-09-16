rule TTP_XOR_QUAD_CurrentVersionRun_6c14 {
  strings:
    $key_6c14 = { 3f 7b [2] 1b 75 [2] 30 59 [2] 1e 7b [2] 0a 60 [2] 05 7a [2] 1b 67 [2] 19 66 [2] 02 60 [2] 1e 67 [2] 02 48 }

  condition:
    any of them
}