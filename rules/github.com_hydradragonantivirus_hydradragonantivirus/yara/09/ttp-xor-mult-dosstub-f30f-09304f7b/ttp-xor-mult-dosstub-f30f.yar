rule TTP_XOR_MULT_DOSStub_f30f {
  strings:
    $key_f30f = { a7 67 [2] d3 7f [2] 94 7d [2] d3 6c [2] 9d 60 [2] 91 6a [2] 86 61 [2] 9d 2f [2] a0 }

  condition:
    any of them
}