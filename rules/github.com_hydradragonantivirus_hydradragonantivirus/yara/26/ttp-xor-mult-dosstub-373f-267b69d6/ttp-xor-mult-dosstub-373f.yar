rule TTP_XOR_MULT_DOSStub_373f {
  strings:
    $key_373f = { 63 57 [2] 17 4f [2] 50 4d [2] 17 5c [2] 59 50 [2] 55 5a [2] 42 51 [2] 59 1f [2] 64 }

  condition:
    any of them
}