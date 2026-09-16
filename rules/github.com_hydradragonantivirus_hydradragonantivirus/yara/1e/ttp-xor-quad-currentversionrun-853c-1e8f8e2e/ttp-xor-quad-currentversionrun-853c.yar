rule TTP_XOR_QUAD_CurrentVersionRun_853c {
  strings:
    $key_853c = { d6 53 [2] f2 5d [2] d9 71 [2] f7 53 [2] e3 48 [2] ec 52 [2] f2 4f [2] f0 4e [2] eb 48 [2] f7 4f [2] eb 60 }

  condition:
    any of them
}