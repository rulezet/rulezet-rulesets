rule TTP_XOR_MULT_DOSStub_7202 {
  strings:
    $key_7202 = { 26 6a [2] 52 72 [2] 15 70 [2] 52 61 [2] 1c 6d [2] 10 67 [2] 07 6c [2] 1c 22 [2] 21 }

  condition:
    any of them
}