rule TTP_XOR_MULT_DOSStub_f34f {
  strings:
    $key_f34f = { a7 27 [2] d3 3f [2] 94 3d [2] d3 2c [2] 9d 20 [2] 91 2a [2] 86 21 [2] 9d 6f [2] a0 }

  condition:
    any of them
}