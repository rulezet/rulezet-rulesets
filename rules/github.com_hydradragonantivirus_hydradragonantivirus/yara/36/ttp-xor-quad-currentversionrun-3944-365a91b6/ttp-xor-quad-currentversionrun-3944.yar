rule TTP_XOR_QUAD_CurrentVersionRun_3944 {
  strings:
    $key_3944 = { 6a 2b [2] 4e 25 [2] 65 09 [2] 4b 2b [2] 5f 30 [2] 50 2a [2] 4e 37 [2] 4c 36 [2] 57 30 [2] 4b 37 [2] 57 18 }

  condition:
    any of them
}