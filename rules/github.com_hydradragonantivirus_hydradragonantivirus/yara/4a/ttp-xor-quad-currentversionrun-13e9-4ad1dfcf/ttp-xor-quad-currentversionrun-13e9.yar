rule TTP_XOR_QUAD_CurrentVersionRun_13e9 {
  strings:
    $key_13e9 = { 40 86 [2] 64 88 [2] 4f a4 [2] 61 86 [2] 75 9d [2] 7a 87 [2] 64 9a [2] 66 9b [2] 7d 9d [2] 61 9a [2] 7d b5 }

  condition:
    any of them
}