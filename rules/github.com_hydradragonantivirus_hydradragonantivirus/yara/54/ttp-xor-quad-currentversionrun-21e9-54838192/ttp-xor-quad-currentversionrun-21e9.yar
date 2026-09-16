rule TTP_XOR_QUAD_CurrentVersionRun_21e9 {
  strings:
    $key_21e9 = { 72 86 [2] 56 88 [2] 7d a4 [2] 53 86 [2] 47 9d [2] 48 87 [2] 56 9a [2] 54 9b [2] 4f 9d [2] 53 9a [2] 4f b5 }

  condition:
    any of them
}