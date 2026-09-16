rule TTP_XOR_QUAD_CurrentVersionRun_a090 {
  strings:
    $key_a090 = { f3 ff [2] d7 f1 [2] fc dd [2] d2 ff [2] c6 e4 [2] c9 fe [2] d7 e3 [2] d5 e2 [2] ce e4 [2] d2 e3 [2] ce cc }

  condition:
    any of them
}