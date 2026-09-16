rule TTP_XOR_MULT_DOSStub_271c {
  strings:
    $key_271c = { 73 74 [2] 07 6c [2] 40 6e [2] 07 7f [2] 49 73 [2] 45 79 [2] 52 72 [2] 49 3c [2] 74 }

  condition:
    any of them
}