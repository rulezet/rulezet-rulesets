rule TTP_XOR_QUAD_CurrentVersionRun_ea35 {
  strings:
    $key_ea35 = { b9 5a [2] 9d 54 [2] b6 78 [2] 98 5a [2] 8c 41 [2] 83 5b [2] 9d 46 [2] 9f 47 [2] 84 41 [2] 98 46 [2] 84 69 }

  condition:
    any of them
}