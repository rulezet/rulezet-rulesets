rule TTP_XOR_QUAD_CurrentVersionRun_8208 {
  strings:
    $key_8208 = { d1 67 [2] f5 69 [2] de 45 [2] f0 67 [2] e4 7c [2] eb 66 [2] f5 7b [2] f7 7a [2] ec 7c [2] f0 7b [2] ec 54 }

  condition:
    any of them
}