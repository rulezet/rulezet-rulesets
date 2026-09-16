rule TTP_XOR_QUAD_CurrentVersionRun_3408 {
  strings:
    $key_3408 = { 67 67 [2] 43 69 [2] 68 45 [2] 46 67 [2] 52 7c [2] 5d 66 [2] 43 7b [2] 41 7a [2] 5a 7c [2] 46 7b [2] 5a 54 }

  condition:
    any of them
}