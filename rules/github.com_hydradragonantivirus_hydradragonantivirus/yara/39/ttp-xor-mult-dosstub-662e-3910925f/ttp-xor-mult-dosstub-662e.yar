rule TTP_XOR_MULT_DOSStub_662e {
  strings:
    $key_662e = { 32 46 [2] 46 5e [2] 01 5c [2] 46 4d [2] 08 41 [2] 04 4b [2] 13 40 [2] 08 0e [2] 35 }

  condition:
    any of them
}