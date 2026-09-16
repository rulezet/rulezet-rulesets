rule TTP_XOR_MULT_DOSStub_0921 {
  strings:
    $key_0921 = { 5d 49 [2] 29 51 [2] 6e 53 [2] 29 42 [2] 67 4e [2] 6b 44 [2] 7c 4f [2] 67 01 [2] 5a }

  condition:
    any of them
}