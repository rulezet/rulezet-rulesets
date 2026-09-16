rule TTP_XOR_QUAD_CurrentVersionRun_3208 {
  strings:
    $key_3208 = { 61 67 [2] 45 69 [2] 6e 45 [2] 40 67 [2] 54 7c [2] 5b 66 [2] 45 7b [2] 47 7a [2] 5c 7c [2] 40 7b [2] 5c 54 }

  condition:
    any of them
}