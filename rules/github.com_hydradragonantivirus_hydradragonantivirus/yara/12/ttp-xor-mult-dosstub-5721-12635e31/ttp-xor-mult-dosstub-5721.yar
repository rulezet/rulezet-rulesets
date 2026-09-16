rule TTP_XOR_MULT_DOSStub_5721 {
  strings:
    $key_5721 = { 03 49 [2] 77 51 [2] 30 53 [2] 77 42 [2] 39 4e [2] 35 44 [2] 22 4f [2] 39 01 [2] 04 }

  condition:
    any of them
}