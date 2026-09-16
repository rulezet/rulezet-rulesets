rule TTP_XOR_MULT_DOSStub_b50f {
  strings:
    $key_b50f = { e1 67 [2] 95 7f [2] d2 7d [2] 95 6c [2] db 60 [2] d7 6a [2] c0 61 [2] db 2f [2] e6 }

  condition:
    any of them
}