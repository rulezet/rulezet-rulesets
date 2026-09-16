rule TTP_XOR_QUAD_CurrentVersionRun_9cfe {
  strings:
    $key_9cfe = { cf 91 [2] eb 9f [2] c0 b3 [2] ee 91 [2] fa 8a [2] f5 90 [2] eb 8d [2] e9 8c [2] f2 8a [2] ee 8d [2] f2 a2 }

  condition:
    any of them
}