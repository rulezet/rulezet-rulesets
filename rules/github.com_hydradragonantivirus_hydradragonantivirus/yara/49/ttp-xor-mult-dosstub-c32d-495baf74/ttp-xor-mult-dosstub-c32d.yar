rule TTP_XOR_MULT_DOSStub_c32d {
  strings:
    $key_c32d = { 97 45 [2] e3 5d [2] a4 5f [2] e3 4e [2] ad 42 [2] a1 48 [2] b6 43 [2] ad 0d [2] 90 }

  condition:
    any of them
}