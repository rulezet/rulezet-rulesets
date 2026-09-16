rule TTP_XOR_MULT_DOSStub_f3ef {
  strings:
    $key_f3ef = { a7 87 [2] d3 9f [2] 94 9d [2] d3 8c [2] 9d 80 [2] 91 8a [2] 86 81 [2] 9d cf [2] a0 }

  condition:
    any of them
}