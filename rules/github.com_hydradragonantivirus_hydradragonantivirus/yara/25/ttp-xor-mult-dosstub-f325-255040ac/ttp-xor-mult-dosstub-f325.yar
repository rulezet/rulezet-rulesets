rule TTP_XOR_MULT_DOSStub_f325 {
  strings:
    $key_f325 = { a7 4d [2] d3 55 [2] 94 57 [2] d3 46 [2] 9d 4a [2] 91 40 [2] 86 4b [2] 9d 05 [2] a0 }

  condition:
    any of them
}