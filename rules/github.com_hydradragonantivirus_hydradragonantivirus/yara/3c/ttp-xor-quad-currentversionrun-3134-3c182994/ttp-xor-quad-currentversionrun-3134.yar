rule TTP_XOR_QUAD_CurrentVersionRun_3134 {
  strings:
    $key_3134 = { 62 5b [2] 46 55 [2] 6d 79 [2] 43 5b [2] 57 40 [2] 58 5a [2] 46 47 [2] 44 46 [2] 5f 40 [2] 43 47 [2] 5f 68 }

  condition:
    any of them
}