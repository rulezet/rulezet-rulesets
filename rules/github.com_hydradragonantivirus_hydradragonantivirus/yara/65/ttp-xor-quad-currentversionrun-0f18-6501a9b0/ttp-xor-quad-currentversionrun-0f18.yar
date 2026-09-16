rule TTP_XOR_QUAD_CurrentVersionRun_0f18 {
  strings:
    $key_0f18 = { 5c 77 [2] 78 79 [2] 53 55 [2] 7d 77 [2] 69 6c [2] 66 76 [2] 78 6b [2] 7a 6a [2] 61 6c [2] 7d 6b [2] 61 44 }

  condition:
    any of them
}