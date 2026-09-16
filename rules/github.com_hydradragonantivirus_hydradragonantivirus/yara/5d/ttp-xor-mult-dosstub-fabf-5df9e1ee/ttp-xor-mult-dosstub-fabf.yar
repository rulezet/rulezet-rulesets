rule TTP_XOR_MULT_DOSStub_fabf {
  strings:
    $key_fabf = { ae d7 [2] da cf [2] 9d cd [2] da dc [2] 94 d0 [2] 98 da [2] 8f d1 [2] 94 9f [2] a9 }

  condition:
    any of them
}