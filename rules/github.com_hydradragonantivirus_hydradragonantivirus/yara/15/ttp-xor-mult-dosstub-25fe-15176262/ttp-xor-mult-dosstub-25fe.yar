rule TTP_XOR_MULT_DOSStub_25fe {
  strings:
    $key_25fe = { 71 96 [2] 05 8e [2] 42 8c [2] 05 9d [2] 4b 91 [2] 47 9b [2] 50 90 [2] 4b de [2] 76 }

  condition:
    any of them
}