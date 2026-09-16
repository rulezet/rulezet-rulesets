rule TTP_XOR_MULT_DOSStub_f399 {
  strings:
    $key_f399 = { a7 f1 [2] d3 e9 [2] 94 eb [2] d3 fa [2] 9d f6 [2] 91 fc [2] 86 f7 [2] 9d b9 [2] a0 }

  condition:
    any of them
}