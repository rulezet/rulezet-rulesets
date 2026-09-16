rule TTP_XOR_MULT_DOSStub_572d {
  strings:
    $key_572d = { 03 45 [2] 77 5d [2] 30 5f [2] 77 4e [2] 39 42 [2] 35 48 [2] 22 43 [2] 39 0d [2] 04 }

  condition:
    any of them
}