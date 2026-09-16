rule TTP_XOR_QUAD_CurrentVersionRun_9be7 {
  strings:
    $key_9be7 = { c8 88 [2] ec 86 [2] c7 aa [2] e9 88 [2] fd 93 [2] f2 89 [2] ec 94 [2] ee 95 [2] f5 93 [2] e9 94 [2] f5 bb }

  condition:
    any of them
}