rule TTP_XOR_QUAD_CurrentVersionRun_3234 {
  strings:
    $key_3234 = { 61 5b [2] 45 55 [2] 6e 79 [2] 40 5b [2] 54 40 [2] 5b 5a [2] 45 47 [2] 47 46 [2] 5c 40 [2] 40 47 [2] 5c 68 }

  condition:
    any of them
}