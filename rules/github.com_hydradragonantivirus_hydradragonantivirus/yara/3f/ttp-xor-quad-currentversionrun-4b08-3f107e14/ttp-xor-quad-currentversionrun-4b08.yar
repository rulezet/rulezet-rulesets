rule TTP_XOR_QUAD_CurrentVersionRun_4b08 {
  strings:
    $key_4b08 = { 18 67 [2] 3c 69 [2] 17 45 [2] 39 67 [2] 2d 7c [2] 22 66 [2] 3c 7b [2] 3e 7a [2] 25 7c [2] 39 7b [2] 25 54 }

  condition:
    any of them
}