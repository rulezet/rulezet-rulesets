rule TTP_XOR_QUAD_CurrentVersionRun_929e {
  strings:
    $key_929e = { c1 f1 [2] e5 ff [2] ce d3 [2] e0 f1 [2] f4 ea [2] fb f0 [2] e5 ed [2] e7 ec [2] fc ea [2] e0 ed [2] fc c2 }

  condition:
    any of them
}