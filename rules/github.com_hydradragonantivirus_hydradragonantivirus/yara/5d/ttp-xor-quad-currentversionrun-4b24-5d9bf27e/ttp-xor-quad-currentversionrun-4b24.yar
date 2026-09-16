rule TTP_XOR_QUAD_CurrentVersionRun_4b24 {
  strings:
    $key_4b24 = { 18 4b [2] 3c 45 [2] 17 69 [2] 39 4b [2] 2d 50 [2] 22 4a [2] 3c 57 [2] 3e 56 [2] 25 50 [2] 39 57 [2] 25 78 }

  condition:
    any of them
}