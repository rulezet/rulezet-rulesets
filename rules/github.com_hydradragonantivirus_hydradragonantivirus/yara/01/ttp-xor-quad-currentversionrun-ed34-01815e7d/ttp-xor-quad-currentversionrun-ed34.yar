rule TTP_XOR_QUAD_CurrentVersionRun_ed34 {
  strings:
    $key_ed34 = { be 5b [2] 9a 55 [2] b1 79 [2] 9f 5b [2] 8b 40 [2] 84 5a [2] 9a 47 [2] 98 46 [2] 83 40 [2] 9f 47 [2] 83 68 }

  condition:
    any of them
}