rule TTP_XOR_QUAD_CurrentVersionRun_07a2 {
  strings:
    $key_07a2 = { 54 cd [2] 70 c3 [2] 5b ef [2] 75 cd [2] 61 d6 [2] 6e cc [2] 70 d1 [2] 72 d0 [2] 69 d6 [2] 75 d1 [2] 69 fe }

  condition:
    any of them
}