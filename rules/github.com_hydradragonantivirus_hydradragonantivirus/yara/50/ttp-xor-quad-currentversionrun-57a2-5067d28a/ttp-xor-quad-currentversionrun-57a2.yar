rule TTP_XOR_QUAD_CurrentVersionRun_57a2 {
  strings:
    $key_57a2 = { 04 cd [2] 20 c3 [2] 0b ef [2] 25 cd [2] 31 d6 [2] 3e cc [2] 20 d1 [2] 22 d0 [2] 39 d6 [2] 25 d1 [2] 39 fe }

  condition:
    any of them
}