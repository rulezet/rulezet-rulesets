rule TTP_XOR_QUAD_CurrentVersionRun_62a2 {
  strings:
    $key_62a2 = { 31 cd [2] 15 c3 [2] 3e ef [2] 10 cd [2] 04 d6 [2] 0b cc [2] 15 d1 [2] 17 d0 [2] 0c d6 [2] 10 d1 [2] 0c fe }

  condition:
    any of them
}