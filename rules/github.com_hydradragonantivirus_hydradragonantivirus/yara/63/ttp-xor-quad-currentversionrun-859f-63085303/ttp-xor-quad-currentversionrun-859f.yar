rule TTP_XOR_QUAD_CurrentVersionRun_859f {
  strings:
    $key_859f = { d6 f0 [2] f2 fe [2] d9 d2 [2] f7 f0 [2] e3 eb [2] ec f1 [2] f2 ec [2] f0 ed [2] eb eb [2] f7 ec [2] eb c3 }

  condition:
    any of them
}