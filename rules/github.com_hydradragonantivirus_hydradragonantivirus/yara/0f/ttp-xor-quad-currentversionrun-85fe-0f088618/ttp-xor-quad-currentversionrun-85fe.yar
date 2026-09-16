rule TTP_XOR_QUAD_CurrentVersionRun_85fe {
  strings:
    $key_85fe = { d6 91 [2] f2 9f [2] d9 b3 [2] f7 91 [2] e3 8a [2] ec 90 [2] f2 8d [2] f0 8c [2] eb 8a [2] f7 8d [2] eb a2 }

  condition:
    any of them
}