rule TTP_XOR_MULT_DOSStub_b30f {
  strings:
    $key_b30f = { e7 67 [2] 93 7f [2] d4 7d [2] 93 6c [2] dd 60 [2] d1 6a [2] c6 61 [2] dd 2f [2] e0 }

  condition:
    any of them
}