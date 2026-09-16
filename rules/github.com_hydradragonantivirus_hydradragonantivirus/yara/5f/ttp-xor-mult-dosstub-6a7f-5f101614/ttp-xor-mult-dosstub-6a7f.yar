rule TTP_XOR_MULT_DOSStub_6a7f {
  strings:
    $key_6a7f = { 3e 17 [2] 4a 0f [2] 0d 0d [2] 4a 1c [2] 04 10 [2] 08 1a [2] 1f 11 [2] 04 5f [2] 39 }

  condition:
    any of them
}