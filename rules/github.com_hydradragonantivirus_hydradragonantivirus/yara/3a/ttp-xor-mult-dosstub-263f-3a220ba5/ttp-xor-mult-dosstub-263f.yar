rule TTP_XOR_MULT_DOSStub_263f {
  strings:
    $key_263f = { 72 57 [2] 06 4f [2] 41 4d [2] 06 5c [2] 48 50 [2] 44 5a [2] 53 51 [2] 48 1f [2] 75 }

  condition:
    any of them
}