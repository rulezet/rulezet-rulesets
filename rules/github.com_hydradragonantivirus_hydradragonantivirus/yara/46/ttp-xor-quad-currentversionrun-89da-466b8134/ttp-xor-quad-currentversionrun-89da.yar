rule TTP_XOR_QUAD_CurrentVersionRun_89da {
  strings:
    $key_89da = { da b5 [2] fe bb [2] d5 97 [2] fb b5 [2] ef ae [2] e0 b4 [2] fe a9 [2] fc a8 [2] e7 ae [2] fb a9 [2] e7 86 }

  condition:
    any of them
}