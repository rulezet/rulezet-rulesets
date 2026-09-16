rule TTP_XOR_MULT_DOSStub_637f {
  strings:
    $key_637f = { 37 17 [2] 43 0f [2] 04 0d [2] 43 1c [2] 0d 10 [2] 01 1a [2] 16 11 [2] 0d 5f [2] 30 }

  condition:
    any of them
}