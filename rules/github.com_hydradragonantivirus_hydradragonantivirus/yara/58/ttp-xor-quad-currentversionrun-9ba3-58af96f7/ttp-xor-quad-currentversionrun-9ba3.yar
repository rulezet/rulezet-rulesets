rule TTP_XOR_QUAD_CurrentVersionRun_9ba3 {
  strings:
    $key_9ba3 = { c8 cc [2] ec c2 [2] c7 ee [2] e9 cc [2] fd d7 [2] f2 cd [2] ec d0 [2] ee d1 [2] f5 d7 [2] e9 d0 [2] f5 ff }

  condition:
    any of them
}