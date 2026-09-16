rule TTP_XOR_MULT_DOSStub_e10f {
  strings:
    $key_e10f = { b5 67 [2] c1 7f [2] 86 7d [2] c1 6c [2] 8f 60 [2] 83 6a [2] 94 61 [2] 8f 2f [2] b2 }

  condition:
    any of them
}