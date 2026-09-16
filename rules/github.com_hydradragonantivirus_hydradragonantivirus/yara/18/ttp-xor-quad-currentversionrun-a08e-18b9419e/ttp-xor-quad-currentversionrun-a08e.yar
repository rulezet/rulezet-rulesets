rule TTP_XOR_QUAD_CurrentVersionRun_a08e {
  strings:
    $key_a08e = { f3 e1 [2] d7 ef [2] fc c3 [2] d2 e1 [2] c6 fa [2] c9 e0 [2] d7 fd [2] d5 fc [2] ce fa [2] d2 fd [2] ce d2 }

  condition:
    any of them
}