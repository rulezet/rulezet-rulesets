rule TTP_XOR_QUAD_CurrentVersionRun_0f38 {
  strings:
    $key_0f38 = { 5c 57 [2] 78 59 [2] 53 75 [2] 7d 57 [2] 69 4c [2] 66 56 [2] 78 4b [2] 7a 4a [2] 61 4c [2] 7d 4b [2] 61 64 }

  condition:
    any of them
}