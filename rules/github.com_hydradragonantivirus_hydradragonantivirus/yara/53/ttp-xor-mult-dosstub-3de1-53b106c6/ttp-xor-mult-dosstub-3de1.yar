rule TTP_XOR_MULT_DOSStub_3de1 {
  strings:
    $key_3de1 = { 69 89 [2] 1d 91 [2] 5a 93 [2] 1d 82 [2] 53 8e [2] 5f 84 [2] 48 8f [2] 53 c1 [2] 6e }

  condition:
    any of them
}