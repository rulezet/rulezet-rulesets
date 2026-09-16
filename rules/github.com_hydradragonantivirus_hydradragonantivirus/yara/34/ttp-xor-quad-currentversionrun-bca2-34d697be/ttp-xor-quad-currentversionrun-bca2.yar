rule TTP_XOR_QUAD_CurrentVersionRun_bca2 {
  strings:
    $key_bca2 = { ef cd [2] cb c3 [2] e0 ef [2] ce cd [2] da d6 [2] d5 cc [2] cb d1 [2] c9 d0 [2] d2 d6 [2] ce d1 [2] d2 fe }

  condition:
    any of them
}