rule TTP_XOR_MULT_DOSStub_f20f {
  strings:
    $key_f20f = { a6 67 [2] d2 7f [2] 95 7d [2] d2 6c [2] 9c 60 [2] 90 6a [2] 87 61 [2] 9c 2f [2] a1 }

  condition:
    any of them
}