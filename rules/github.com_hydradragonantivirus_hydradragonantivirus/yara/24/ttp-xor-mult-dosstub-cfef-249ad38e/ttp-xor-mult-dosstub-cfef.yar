rule TTP_XOR_MULT_DOSStub_cfef {
  strings:
    $key_cfef = { 9b 87 [2] ef 9f [2] a8 9d [2] ef 8c [2] a1 80 [2] ad 8a [2] ba 81 [2] a1 cf [2] 9c }

  condition:
    any of them
}