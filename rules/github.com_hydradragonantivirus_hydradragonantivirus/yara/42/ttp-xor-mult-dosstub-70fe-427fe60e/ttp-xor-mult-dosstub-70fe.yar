rule TTP_XOR_MULT_DOSStub_70fe {
  strings:
    $key_70fe = { 24 96 [2] 50 8e [2] 17 8c [2] 50 9d [2] 1e 91 [2] 12 9b [2] 05 90 [2] 1e de [2] 23 }

  condition:
    any of them
}