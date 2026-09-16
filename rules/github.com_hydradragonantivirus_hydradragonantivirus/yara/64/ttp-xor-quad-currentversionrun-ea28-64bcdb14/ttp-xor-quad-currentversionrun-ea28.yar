rule TTP_XOR_QUAD_CurrentVersionRun_ea28 {
  strings:
    $key_ea28 = { b9 47 [2] 9d 49 [2] b6 65 [2] 98 47 [2] 8c 5c [2] 83 46 [2] 9d 5b [2] 9f 5a [2] 84 5c [2] 98 5b [2] 84 74 }

  condition:
    any of them
}