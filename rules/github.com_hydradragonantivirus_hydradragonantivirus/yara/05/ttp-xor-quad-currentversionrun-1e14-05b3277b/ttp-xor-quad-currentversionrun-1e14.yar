rule TTP_XOR_QUAD_CurrentVersionRun_1e14 {
  strings:
    $key_1e14 = { 4d 7b [2] 69 75 [2] 42 59 [2] 6c 7b [2] 78 60 [2] 77 7a [2] 69 67 [2] 6b 66 [2] 70 60 [2] 6c 67 [2] 70 48 }

  condition:
    any of them
}