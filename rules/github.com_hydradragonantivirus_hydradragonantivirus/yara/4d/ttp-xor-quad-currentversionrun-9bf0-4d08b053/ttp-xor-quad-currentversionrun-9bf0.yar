rule TTP_XOR_QUAD_CurrentVersionRun_9bf0 {
  strings:
    $key_9bf0 = { c8 9f [2] ec 91 [2] c7 bd [2] e9 9f [2] fd 84 [2] f2 9e [2] ec 83 [2] ee 82 [2] f5 84 [2] e9 83 [2] f5 ac }

  condition:
    any of them
}