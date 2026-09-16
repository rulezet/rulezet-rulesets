rule TTP_XOR_QUAD_CurrentVersionRun_eb35 {
  strings:
    $key_eb35 = { b8 5a [2] 9c 54 [2] b7 78 [2] 99 5a [2] 8d 41 [2] 82 5b [2] 9c 46 [2] 9e 47 [2] 85 41 [2] 99 46 [2] 85 69 }

  condition:
    any of them
}