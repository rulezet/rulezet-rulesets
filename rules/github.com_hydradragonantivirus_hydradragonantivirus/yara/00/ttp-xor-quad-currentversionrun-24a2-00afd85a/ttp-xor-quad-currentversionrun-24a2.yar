rule TTP_XOR_QUAD_CurrentVersionRun_24a2 {
  strings:
    $key_24a2 = { 77 cd [2] 53 c3 [2] 78 ef [2] 56 cd [2] 42 d6 [2] 4d cc [2] 53 d1 [2] 51 d0 [2] 4a d6 [2] 56 d1 [2] 4a fe }

  condition:
    any of them
}