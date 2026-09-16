rule TTP_XOR_QUAD_CurrentVersionRun_851c {
  strings:
    $key_851c = { d6 73 [2] f2 7d [2] d9 51 [2] f7 73 [2] e3 68 [2] ec 72 [2] f2 6f [2] f0 6e [2] eb 68 [2] f7 6f [2] eb 40 }

  condition:
    any of them
}