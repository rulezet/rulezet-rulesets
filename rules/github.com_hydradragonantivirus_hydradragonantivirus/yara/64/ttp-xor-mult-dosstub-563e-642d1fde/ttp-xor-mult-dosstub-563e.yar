rule TTP_XOR_MULT_DOSStub_563e {
  strings:
    $key_563e = { 02 56 [2] 76 4e [2] 31 4c [2] 76 5d [2] 38 51 [2] 34 5b [2] 23 50 [2] 38 1e [2] 05 }

  condition:
    any of them
}