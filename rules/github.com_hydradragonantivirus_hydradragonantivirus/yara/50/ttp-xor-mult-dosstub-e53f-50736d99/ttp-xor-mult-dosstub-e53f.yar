rule TTP_XOR_MULT_DOSStub_e53f {
  strings:
    $key_e53f = { b1 57 [2] c5 4f [2] 82 4d [2] c5 5c [2] 8b 50 [2] 87 5a [2] 90 51 [2] 8b 1f [2] b6 }

  condition:
    any of them
}