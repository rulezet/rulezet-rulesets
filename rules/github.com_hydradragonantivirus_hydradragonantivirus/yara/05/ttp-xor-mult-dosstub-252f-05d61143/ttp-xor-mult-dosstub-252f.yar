rule TTP_XOR_MULT_DOSStub_252f {
  strings:
    $key_252f = { 71 47 [2] 05 5f [2] 42 5d [2] 05 4c [2] 4b 40 [2] 47 4a [2] 50 41 [2] 4b 0f [2] 76 }

  condition:
    any of them
}