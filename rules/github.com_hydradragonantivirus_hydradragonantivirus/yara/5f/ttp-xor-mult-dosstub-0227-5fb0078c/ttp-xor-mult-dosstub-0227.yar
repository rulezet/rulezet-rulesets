rule TTP_XOR_MULT_DOSStub_0227 {
  strings:
    $key_0227 = { 56 4f [2] 22 57 [2] 65 55 [2] 22 44 [2] 6c 48 [2] 60 42 [2] 77 49 [2] 6c 07 [2] 51 }

  condition:
    any of them
}