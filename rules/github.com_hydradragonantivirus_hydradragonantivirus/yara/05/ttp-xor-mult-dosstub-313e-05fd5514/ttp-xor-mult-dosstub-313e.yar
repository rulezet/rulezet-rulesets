rule TTP_XOR_MULT_DOSStub_313e {
  strings:
    $key_313e = { 65 56 [2] 11 4e [2] 56 4c [2] 11 5d [2] 5f 51 [2] 53 5b [2] 44 50 [2] 5f 1e [2] 62 }

  condition:
    any of them
}