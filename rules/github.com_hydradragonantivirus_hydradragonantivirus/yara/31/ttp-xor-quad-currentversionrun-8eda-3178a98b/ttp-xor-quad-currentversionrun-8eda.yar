rule TTP_XOR_QUAD_CurrentVersionRun_8eda {
  strings:
    $key_8eda = { dd b5 [2] f9 bb [2] d2 97 [2] fc b5 [2] e8 ae [2] e7 b4 [2] f9 a9 [2] fb a8 [2] e0 ae [2] fc a9 [2] e0 86 }

  condition:
    any of them
}