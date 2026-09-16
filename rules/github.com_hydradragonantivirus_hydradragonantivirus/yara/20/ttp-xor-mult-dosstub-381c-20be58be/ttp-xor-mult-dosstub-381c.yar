rule TTP_XOR_MULT_DOSStub_381c {
  strings:
    $key_381c = { 6c 74 [2] 18 6c [2] 5f 6e [2] 18 7f [2] 56 73 [2] 5a 79 [2] 4d 72 [2] 56 3c [2] 6b }

  condition:
    any of them
}