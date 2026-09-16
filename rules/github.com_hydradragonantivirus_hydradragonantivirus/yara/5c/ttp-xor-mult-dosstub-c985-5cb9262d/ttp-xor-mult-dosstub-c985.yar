rule TTP_XOR_MULT_DOSStub_c985 {
  strings:
    $key_c985 = { 9d ed [2] e9 f5 [2] ae f7 [2] e9 e6 [2] a7 ea [2] ab e0 [2] bc eb [2] a7 a5 [2] 9a }

  condition:
    any of them
}