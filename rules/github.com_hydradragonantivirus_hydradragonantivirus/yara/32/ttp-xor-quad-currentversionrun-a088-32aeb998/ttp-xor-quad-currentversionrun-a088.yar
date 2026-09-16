rule TTP_XOR_QUAD_CurrentVersionRun_a088 {
  strings:
    $key_a088 = { f3 e7 [2] d7 e9 [2] fc c5 [2] d2 e7 [2] c6 fc [2] c9 e6 [2] d7 fb [2] d5 fa [2] ce fc [2] d2 fb [2] ce d4 }

  condition:
    any of them
}