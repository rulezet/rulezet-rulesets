rule TTP_XOR_MULT_DOSStub_cfff {
  strings:
    $key_cfff = { 9b 97 [2] ef 8f [2] a8 8d [2] ef 9c [2] a1 90 [2] ad 9a [2] ba 91 [2] a1 df [2] 9c }

  condition:
    any of them
}