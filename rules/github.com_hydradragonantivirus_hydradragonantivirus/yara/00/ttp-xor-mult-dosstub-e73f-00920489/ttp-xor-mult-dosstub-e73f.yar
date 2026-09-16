rule TTP_XOR_MULT_DOSStub_e73f {
  strings:
    $key_e73f = { b3 57 [2] c7 4f [2] 80 4d [2] c7 5c [2] 89 50 [2] 85 5a [2] 92 51 [2] 89 1f [2] b4 }

  condition:
    any of them
}