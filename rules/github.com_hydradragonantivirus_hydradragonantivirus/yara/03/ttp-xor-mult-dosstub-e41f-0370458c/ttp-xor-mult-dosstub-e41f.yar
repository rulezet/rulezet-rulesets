rule TTP_XOR_MULT_DOSStub_e41f {
  strings:
    $key_e41f = { b0 77 [2] c4 6f [2] 83 6d [2] c4 7c [2] 8a 70 [2] 86 7a [2] 91 71 [2] 8a 3f [2] b7 }

  condition:
    any of them
}