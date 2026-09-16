rule TTP_XOR_MULT_DOSStub_0231 {
  strings:
    $key_0231 = { 56 59 [2] 22 41 [2] 65 43 [2] 22 52 [2] 6c 5e [2] 60 54 [2] 77 5f [2] 6c 11 [2] 51 }

  condition:
    any of them
}