rule TTP_XOR_MULT_DOSStub_f6fd {
  strings:
    $key_f6fd = { a2 95 [2] d6 8d [2] 91 8f [2] d6 9e [2] 98 92 [2] 94 98 [2] 83 93 [2] 98 dd [2] a5 }

  condition:
    any of them
}