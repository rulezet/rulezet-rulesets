rule TTP_XOR_MULT_DOSStub_f3ea {
  strings:
    $key_f3ea = { a7 82 [2] d3 9a [2] 94 98 [2] d3 89 [2] 9d 85 [2] 91 8f [2] 86 84 [2] 9d ca [2] a0 }

  condition:
    any of them
}