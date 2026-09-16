rule TTP_XOR_QUAD_CurrentVersionRun_85e1 {
  strings:
    $key_85e1 = { d6 8e [2] f2 80 [2] d9 ac [2] f7 8e [2] e3 95 [2] ec 8f [2] f2 92 [2] f0 93 [2] eb 95 [2] f7 92 [2] eb bd }

  condition:
    any of them
}