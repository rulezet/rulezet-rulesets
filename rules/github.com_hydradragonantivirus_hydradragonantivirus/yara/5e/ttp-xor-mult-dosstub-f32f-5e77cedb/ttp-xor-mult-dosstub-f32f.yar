rule TTP_XOR_MULT_DOSStub_f32f {
  strings:
    $key_f32f = { a7 47 [2] d3 5f [2] 94 5d [2] d3 4c [2] 9d 40 [2] 91 4a [2] 86 41 [2] 9d 0f [2] a0 }

  condition:
    any of them
}