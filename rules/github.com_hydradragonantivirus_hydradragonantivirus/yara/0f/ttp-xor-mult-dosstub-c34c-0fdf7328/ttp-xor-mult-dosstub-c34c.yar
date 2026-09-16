rule TTP_XOR_MULT_DOSStub_c34c {
  strings:
    $key_c34c = { 97 24 [2] e3 3c [2] a4 3e [2] e3 2f [2] ad 23 [2] a1 29 [2] b6 22 [2] ad 6c [2] 90 }

  condition:
    any of them
}