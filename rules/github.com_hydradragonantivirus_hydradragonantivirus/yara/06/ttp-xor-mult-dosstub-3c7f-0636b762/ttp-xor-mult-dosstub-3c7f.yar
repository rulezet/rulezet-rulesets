rule TTP_XOR_MULT_DOSStub_3c7f {
  strings:
    $key_3c7f = { 68 17 [2] 1c 0f [2] 5b 0d [2] 1c 1c [2] 52 10 [2] 5e 1a [2] 49 11 [2] 52 5f [2] 6f }

  condition:
    any of them
}