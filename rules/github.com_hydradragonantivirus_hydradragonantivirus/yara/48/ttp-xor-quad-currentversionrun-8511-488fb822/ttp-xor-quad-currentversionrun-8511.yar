rule TTP_XOR_QUAD_CurrentVersionRun_8511 {
  strings:
    $key_8511 = { d6 7e [2] f2 70 [2] d9 5c [2] f7 7e [2] e3 65 [2] ec 7f [2] f2 62 [2] f0 63 [2] eb 65 [2] f7 62 [2] eb 4d }

  condition:
    any of them
}