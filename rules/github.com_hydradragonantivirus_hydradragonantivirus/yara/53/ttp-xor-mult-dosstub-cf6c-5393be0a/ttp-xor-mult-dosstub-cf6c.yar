rule TTP_XOR_MULT_DOSStub_cf6c {
  strings:
    $key_cf6c = { 9b 04 [2] ef 1c [2] a8 1e [2] ef 0f [2] a1 03 [2] ad 09 [2] ba 02 [2] a1 4c [2] 9c }

  condition:
    any of them
}