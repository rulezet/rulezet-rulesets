rule TTP_XOR_MULT_DOSStub_0bbf {
  strings:
    $key_0bbf = { 5f d7 [2] 2b cf [2] 6c cd [2] 2b dc [2] 65 d0 [2] 69 da [2] 7e d1 [2] 65 9f [2] 58 }

  condition:
    any of them
}