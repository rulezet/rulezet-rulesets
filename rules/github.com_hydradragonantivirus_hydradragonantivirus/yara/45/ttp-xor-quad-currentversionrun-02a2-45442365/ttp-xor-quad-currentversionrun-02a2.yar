rule TTP_XOR_QUAD_CurrentVersionRun_02a2 {
  strings:
    $key_02a2 = { 51 cd [2] 75 c3 [2] 5e ef [2] 70 cd [2] 64 d6 [2] 6b cc [2] 75 d1 [2] 77 d0 [2] 6c d6 [2] 70 d1 [2] 6c fe }

  condition:
    any of them
}