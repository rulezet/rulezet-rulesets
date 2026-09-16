rule TTP_XOR_QUAD_CurrentVersionRun_85ff {
  strings:
    $key_85ff = { d6 90 [2] f2 9e [2] d9 b2 [2] f7 90 [2] e3 8b [2] ec 91 [2] f2 8c [2] f0 8d [2] eb 8b [2] f7 8c [2] eb a3 }

  condition:
    any of them
}