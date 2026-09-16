rule TTP_XOR_QUAD_CurrentVersionRun_0729 {
  strings:
    $key_0729 = { 54 46 [2] 70 48 [2] 5b 64 [2] 75 46 [2] 61 5d [2] 6e 47 [2] 70 5a [2] 72 5b [2] 69 5d [2] 75 5a [2] 69 75 }

  condition:
    any of them
}