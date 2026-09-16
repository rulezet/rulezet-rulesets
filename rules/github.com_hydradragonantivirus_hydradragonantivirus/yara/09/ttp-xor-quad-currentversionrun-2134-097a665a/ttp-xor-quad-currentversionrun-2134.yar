rule TTP_XOR_QUAD_CurrentVersionRun_2134 {
  strings:
    $key_2134 = { 72 5b [2] 56 55 [2] 7d 79 [2] 53 5b [2] 47 40 [2] 48 5a [2] 56 47 [2] 54 46 [2] 4f 40 [2] 53 47 [2] 4f 68 }

  condition:
    any of them
}