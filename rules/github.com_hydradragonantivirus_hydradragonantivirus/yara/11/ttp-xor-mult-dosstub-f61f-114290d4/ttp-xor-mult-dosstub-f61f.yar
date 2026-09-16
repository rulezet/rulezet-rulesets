rule TTP_XOR_MULT_DOSStub_f61f {
  strings:
    $key_f61f = { a2 77 [2] d6 6f [2] 91 6d [2] d6 7c [2] 98 70 [2] 94 7a [2] 83 71 [2] 98 3f [2] a5 }

  condition:
    any of them
}