rule TTP_XOR_MULT_DOSStub_4bbf {
  strings:
    $key_4bbf = { 1f d7 [2] 6b cf [2] 2c cd [2] 6b dc [2] 25 d0 [2] 29 da [2] 3e d1 [2] 25 9f [2] 18 }

  condition:
    any of them
}