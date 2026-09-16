rule TTP_XOR_MULT_DOSStub_242c {
  strings:
    $key_242c = { 70 44 [2] 04 5c [2] 43 5e [2] 04 4f [2] 4a 43 [2] 46 49 [2] 51 42 [2] 4a 0c [2] 77 }

  condition:
    any of them
}