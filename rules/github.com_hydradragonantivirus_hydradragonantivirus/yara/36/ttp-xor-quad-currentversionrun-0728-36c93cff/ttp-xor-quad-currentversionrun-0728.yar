rule TTP_XOR_QUAD_CurrentVersionRun_0728 {
  strings:
    $key_0728 = { 54 47 [2] 70 49 [2] 5b 65 [2] 75 47 [2] 61 5c [2] 6e 46 [2] 70 5b [2] 72 5a [2] 69 5c [2] 75 5b [2] 69 74 }

  condition:
    any of them
}