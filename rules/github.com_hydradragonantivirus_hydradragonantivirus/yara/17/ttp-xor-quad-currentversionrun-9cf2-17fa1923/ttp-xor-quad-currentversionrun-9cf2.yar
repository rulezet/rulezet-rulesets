rule TTP_XOR_QUAD_CurrentVersionRun_9cf2 {
  strings:
    $key_9cf2 = { cf 9d [2] eb 93 [2] c0 bf [2] ee 9d [2] fa 86 [2] f5 9c [2] eb 81 [2] e9 80 [2] f2 86 [2] ee 81 [2] f2 ae }

  condition:
    any of them
}