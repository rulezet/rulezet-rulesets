rule TTP_XOR_QUAD_CurrentVersionRun_11a2 {
  strings:
    $key_11a2 = { 42 cd [2] 66 c3 [2] 4d ef [2] 63 cd [2] 77 d6 [2] 78 cc [2] 66 d1 [2] 64 d0 [2] 7f d6 [2] 63 d1 [2] 7f fe }

  condition:
    any of them
}