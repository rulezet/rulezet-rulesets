rule TTP_XOR_QUAD_CurrentVersionRun_a89f {
  strings:
    $key_a89f = { fb f0 [2] df fe [2] f4 d2 [2] da f0 [2] ce eb [2] c1 f1 [2] df ec [2] dd ed [2] c6 eb [2] da ec [2] c6 c3 }

  condition:
    any of them
}