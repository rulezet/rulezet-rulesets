rule TTP_XOR_QUAD_CurrentVersionRun_7e38 {
  strings:
    $key_7e38 = { 2d 57 [2] 09 59 [2] 22 75 [2] 0c 57 [2] 18 4c [2] 17 56 [2] 09 4b [2] 0b 4a [2] 10 4c [2] 0c 4b [2] 10 64 }

  condition:
    any of them
}