rule TTP_XOR_QUAD_CurrentVersionRun_9ba2 {
  strings:
    $key_9ba2 = { c8 cd [2] ec c3 [2] c7 ef [2] e9 cd [2] fd d6 [2] f2 cc [2] ec d1 [2] ee d0 [2] f5 d6 [2] e9 d1 [2] f5 fe }

  condition:
    any of them
}