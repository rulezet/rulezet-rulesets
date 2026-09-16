rule TTP_XOR_QUAD_CurrentVersionRun_85f2 {
  strings:
    $key_85f2 = { d6 9d [2] f2 93 [2] d9 bf [2] f7 9d [2] e3 86 [2] ec 9c [2] f2 81 [2] f0 80 [2] eb 86 [2] f7 81 [2] eb ae }

  condition:
    any of them
}