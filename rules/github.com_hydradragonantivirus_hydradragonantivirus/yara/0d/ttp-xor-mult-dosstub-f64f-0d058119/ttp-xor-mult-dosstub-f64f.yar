rule TTP_XOR_MULT_DOSStub_f64f {
  strings:
    $key_f64f = { a2 27 [2] d6 3f [2] 91 3d [2] d6 2c [2] 98 20 [2] 94 2a [2] 83 21 [2] 98 6f [2] a5 }

  condition:
    any of them
}