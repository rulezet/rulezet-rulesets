rule TTP_XOR_QUAD_CurrentVersionRun_173b {
  strings:
    $key_173b = { 44 54 [2] 60 5a [2] 4b 76 [2] 65 54 [2] 71 4f [2] 7e 55 [2] 60 48 [2] 62 49 [2] 79 4f [2] 65 48 [2] 79 67 }

  condition:
    any of them
}