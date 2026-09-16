rule TTP_XOR_QUAD_CurrentVersionRun_8510 {
  strings:
    $key_8510 = { d6 7f [2] f2 71 [2] d9 5d [2] f7 7f [2] e3 64 [2] ec 7e [2] f2 63 [2] f0 62 [2] eb 64 [2] f7 63 [2] eb 4c }

  condition:
    any of them
}