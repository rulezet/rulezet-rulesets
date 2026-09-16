rule TTP_XOR_MULT_DOSStub_7bbf {
  strings:
    $key_7bbf = { 2f d7 [2] 5b cf [2] 1c cd [2] 5b dc [2] 15 d0 [2] 19 da [2] 0e d1 [2] 15 9f [2] 28 }

  condition:
    any of them
}