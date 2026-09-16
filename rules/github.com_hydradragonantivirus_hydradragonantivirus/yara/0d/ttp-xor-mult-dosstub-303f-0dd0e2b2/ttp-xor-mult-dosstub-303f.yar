rule TTP_XOR_MULT_DOSStub_303f {
  strings:
    $key_303f = { 64 57 [2] 10 4f [2] 57 4d [2] 10 5c [2] 5e 50 [2] 52 5a [2] 45 51 [2] 5e 1f [2] 63 }

  condition:
    any of them
}