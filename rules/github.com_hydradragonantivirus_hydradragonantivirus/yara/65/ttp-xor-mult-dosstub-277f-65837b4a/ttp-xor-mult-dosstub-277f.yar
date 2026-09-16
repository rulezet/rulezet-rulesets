rule TTP_XOR_MULT_DOSStub_277f {
  strings:
    $key_277f = { 73 17 [2] 07 0f [2] 40 0d [2] 07 1c [2] 49 10 [2] 45 1a [2] 52 11 [2] 49 5f [2] 74 }

  condition:
    any of them
}