rule TTP_XOR_QUAD_CurrentVersionRun_4b38 {
  strings:
    $key_4b38 = { 18 57 [2] 3c 59 [2] 17 75 [2] 39 57 [2] 2d 4c [2] 22 56 [2] 3c 4b [2] 3e 4a [2] 25 4c [2] 39 4b [2] 25 64 }

  condition:
    any of them
}