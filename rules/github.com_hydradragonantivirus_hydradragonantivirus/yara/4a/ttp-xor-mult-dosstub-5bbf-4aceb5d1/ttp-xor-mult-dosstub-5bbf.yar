rule TTP_XOR_MULT_DOSStub_5bbf {
  strings:
    $key_5bbf = { 0f d7 [2] 7b cf [2] 3c cd [2] 7b dc [2] 35 d0 [2] 39 da [2] 2e d1 [2] 35 9f [2] 08 }

  condition:
    any of them
}