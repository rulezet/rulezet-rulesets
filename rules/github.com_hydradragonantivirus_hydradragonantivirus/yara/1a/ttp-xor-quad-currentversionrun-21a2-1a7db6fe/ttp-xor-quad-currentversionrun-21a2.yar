rule TTP_XOR_QUAD_CurrentVersionRun_21a2 {
  strings:
    $key_21a2 = { 72 cd [2] 56 c3 [2] 7d ef [2] 53 cd [2] 47 d6 [2] 48 cc [2] 56 d1 [2] 54 d0 [2] 4f d6 [2] 53 d1 [2] 4f fe }

  condition:
    any of them
}