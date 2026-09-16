rule TTP_XOR_QUAD_CurrentVersionRun_835c {
  strings:
    $key_835c = { d0 33 [2] f4 3d [2] df 11 [2] f1 33 [2] e5 28 [2] ea 32 [2] f4 2f [2] f6 2e [2] ed 28 [2] f1 2f [2] ed 00 }

  condition:
    any of them
}