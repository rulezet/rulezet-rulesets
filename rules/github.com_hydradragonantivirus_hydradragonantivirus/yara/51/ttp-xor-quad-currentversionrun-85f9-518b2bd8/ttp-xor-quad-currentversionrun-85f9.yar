rule TTP_XOR_QUAD_CurrentVersionRun_85f9 {
  strings:
    $key_85f9 = { d6 96 [2] f2 98 [2] d9 b4 [2] f7 96 [2] e3 8d [2] ec 97 [2] f2 8a [2] f0 8b [2] eb 8d [2] f7 8a [2] eb a5 }

  condition:
    any of them
}