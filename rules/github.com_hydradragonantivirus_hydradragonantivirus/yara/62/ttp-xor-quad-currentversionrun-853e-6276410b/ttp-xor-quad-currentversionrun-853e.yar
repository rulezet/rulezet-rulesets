rule TTP_XOR_QUAD_CurrentVersionRun_853e {
  strings:
    $key_853e = { d6 51 [2] f2 5f [2] d9 73 [2] f7 51 [2] e3 4a [2] ec 50 [2] f2 4d [2] f0 4c [2] eb 4a [2] f7 4d [2] eb 62 }

  condition:
    any of them
}