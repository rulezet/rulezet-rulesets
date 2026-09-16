rule TTP_XOR_MULT_DOSStub_370f {
  strings:
    $key_370f = { 63 67 [2] 17 7f [2] 50 7d [2] 17 6c [2] 59 60 [2] 55 6a [2] 42 61 [2] 59 2f [2] 64 }

  condition:
    any of them
}