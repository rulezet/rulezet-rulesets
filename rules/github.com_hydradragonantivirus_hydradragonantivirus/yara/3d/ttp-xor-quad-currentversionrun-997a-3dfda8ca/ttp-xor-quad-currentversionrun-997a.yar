rule TTP_XOR_QUAD_CurrentVersionRun_997a {
  strings:
    $key_997a = { ca 15 [2] ee 1b [2] c5 37 [2] eb 15 [2] ff 0e [2] f0 14 [2] ee 09 [2] ec 08 [2] f7 0e [2] eb 09 [2] f7 26 }

  condition:
    any of them
}