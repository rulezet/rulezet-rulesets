rule TTP_XOR_MULT_DOSStub_0221 {
  strings:
    $key_0221 = { 56 49 [2] 22 51 [2] 65 53 [2] 22 42 [2] 6c 4e [2] 60 44 [2] 77 4f [2] 6c 01 [2] 51 }

  condition:
    any of them
}