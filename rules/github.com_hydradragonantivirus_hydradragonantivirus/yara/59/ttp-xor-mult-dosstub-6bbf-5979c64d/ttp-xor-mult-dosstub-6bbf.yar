rule TTP_XOR_MULT_DOSStub_6bbf {
  strings:
    $key_6bbf = { 3f d7 [2] 4b cf [2] 0c cd [2] 4b dc [2] 05 d0 [2] 09 da [2] 1e d1 [2] 05 9f [2] 38 }

  condition:
    any of them
}