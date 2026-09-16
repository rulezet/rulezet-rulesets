rule TTP_XOR_QUAD_CurrentVersionRun_2128 {
  strings:
    $key_2128 = { 72 47 [2] 56 49 [2] 7d 65 [2] 53 47 [2] 47 5c [2] 48 46 [2] 56 5b [2] 54 5a [2] 4f 5c [2] 53 5b [2] 4f 74 }

  condition:
    any of them
}