rule TTP_XOR_QUAD_CurrentVersionRun_82ee {
  strings:
    $key_82ee = { d1 81 [2] f5 8f [2] de a3 [2] f0 81 [2] e4 9a [2] eb 80 [2] f5 9d [2] f7 9c [2] ec 9a [2] f0 9d [2] ec b2 }

  condition:
    any of them
}