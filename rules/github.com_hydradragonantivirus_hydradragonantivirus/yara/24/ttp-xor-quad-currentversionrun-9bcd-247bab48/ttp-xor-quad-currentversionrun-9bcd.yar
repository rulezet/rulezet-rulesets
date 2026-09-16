rule TTP_XOR_QUAD_CurrentVersionRun_9bcd {
  strings:
    $key_9bcd = { c8 a2 [2] ec ac [2] c7 80 [2] e9 a2 [2] fd b9 [2] f2 a3 [2] ec be [2] ee bf [2] f5 b9 [2] e9 be [2] f5 91 }

  condition:
    any of them
}