rule TTP_XOR_MULT_DOSStub_f61c {
  strings:
    $key_f61c = { a2 74 [2] d6 6c [2] 91 6e [2] d6 7f [2] 98 73 [2] 94 79 [2] 83 72 [2] 98 3c [2] a5 }

  condition:
    any of them
}