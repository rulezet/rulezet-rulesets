rule TTP_XOR_QUAD_CurrentVersionRun_37a2 {
  strings:
    $key_37a2 = { 64 cd [2] 40 c3 [2] 6b ef [2] 45 cd [2] 51 d6 [2] 5e cc [2] 40 d1 [2] 42 d0 [2] 59 d6 [2] 45 d1 [2] 59 fe }

  condition:
    any of them
}