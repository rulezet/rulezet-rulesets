rule TTP_XOR_MULT_DOSStub_1921 {
  strings:
    $key_1921 = { 4d 49 [2] 39 51 [2] 7e 53 [2] 39 42 [2] 77 4e [2] 7b 44 [2] 6c 4f [2] 77 01 [2] 4a }

  condition:
    any of them
}