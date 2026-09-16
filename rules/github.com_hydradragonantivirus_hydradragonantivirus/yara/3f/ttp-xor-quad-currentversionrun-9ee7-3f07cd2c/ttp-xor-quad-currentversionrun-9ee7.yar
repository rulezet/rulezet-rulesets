rule TTP_XOR_QUAD_CurrentVersionRun_9ee7 {
  strings:
    $key_9ee7 = { cd 88 [2] e9 86 [2] c2 aa [2] ec 88 [2] f8 93 [2] f7 89 [2] e9 94 [2] eb 95 [2] f0 93 [2] ec 94 [2] f0 bb }

  condition:
    any of them
}