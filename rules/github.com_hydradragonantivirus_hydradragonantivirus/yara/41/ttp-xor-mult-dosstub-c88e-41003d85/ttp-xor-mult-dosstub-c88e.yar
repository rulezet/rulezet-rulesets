rule TTP_XOR_MULT_DOSStub_c88e {
  strings:
    $key_c88e = { 9c e6 [2] e8 fe [2] af fc [2] e8 ed [2] a6 e1 [2] aa eb [2] bd e0 [2] a6 ae [2] 9b }

  condition:
    any of them
}