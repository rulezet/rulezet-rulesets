rule TTP_XOR_MULT_DOSStub_6b1c {
  strings:
    $key_6b1c = { 3f 74 [2] 4b 6c [2] 0c 6e [2] 4b 7f [2] 05 73 [2] 09 79 [2] 1e 72 [2] 05 3c [2] 38 }

  condition:
    any of them
}