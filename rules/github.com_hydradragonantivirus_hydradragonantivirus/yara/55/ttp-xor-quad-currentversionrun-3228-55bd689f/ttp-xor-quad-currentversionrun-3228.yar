rule TTP_XOR_QUAD_CurrentVersionRun_3228 {
  strings:
    $key_3228 = { 61 47 [2] 45 49 [2] 6e 65 [2] 40 47 [2] 54 5c [2] 5b 46 [2] 45 5b [2] 47 5a [2] 5c 5c [2] 40 5b [2] 5c 74 }

  condition:
    any of them
}