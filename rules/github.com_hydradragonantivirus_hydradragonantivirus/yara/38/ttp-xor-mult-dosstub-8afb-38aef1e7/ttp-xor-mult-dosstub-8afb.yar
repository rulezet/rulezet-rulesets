rule TTP_XOR_MULT_DOSStub_8afb {
  strings:
    $key_8afb = { de 93 [2] aa 8b [2] ed 89 [2] aa 98 [2] e4 94 [2] e8 9e [2] ff 95 [2] e4 db [2] d9 }

  condition:
    any of them
}