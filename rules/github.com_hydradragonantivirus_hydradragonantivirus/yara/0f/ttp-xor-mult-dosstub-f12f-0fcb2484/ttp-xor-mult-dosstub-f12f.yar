rule TTP_XOR_MULT_DOSStub_f12f {
  strings:
    $key_f12f = { a5 47 [2] d1 5f [2] 96 5d [2] d1 4c [2] 9f 40 [2] 93 4a [2] 84 41 [2] 9f 0f [2] a2 }

  condition:
    any of them
}