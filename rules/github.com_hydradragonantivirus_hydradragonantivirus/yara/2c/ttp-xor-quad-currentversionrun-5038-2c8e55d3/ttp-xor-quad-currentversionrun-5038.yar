rule TTP_XOR_QUAD_CurrentVersionRun_5038 {
  strings:
    $key_5038 = { 03 57 [2] 27 59 [2] 0c 75 [2] 22 57 [2] 36 4c [2] 39 56 [2] 27 4b [2] 25 4a [2] 3e 4c [2] 22 4b [2] 3e 64 }

  condition:
    any of them
}