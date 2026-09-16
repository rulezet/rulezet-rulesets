rule TTP_XOR_MULT_DOSStub_f36f {
  strings:
    $key_f36f = { a7 07 [2] d3 1f [2] 94 1d [2] d3 0c [2] 9d 00 [2] 91 0a [2] 86 01 [2] 9d 4f [2] a0 }

  condition:
    any of them
}