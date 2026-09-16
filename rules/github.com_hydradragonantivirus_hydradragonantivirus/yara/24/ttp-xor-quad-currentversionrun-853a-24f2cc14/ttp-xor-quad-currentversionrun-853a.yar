rule TTP_XOR_QUAD_CurrentVersionRun_853a {
  strings:
    $key_853a = { d6 55 [2] f2 5b [2] d9 77 [2] f7 55 [2] e3 4e [2] ec 54 [2] f2 49 [2] f0 48 [2] eb 4e [2] f7 49 [2] eb 66 }

  condition:
    any of them
}