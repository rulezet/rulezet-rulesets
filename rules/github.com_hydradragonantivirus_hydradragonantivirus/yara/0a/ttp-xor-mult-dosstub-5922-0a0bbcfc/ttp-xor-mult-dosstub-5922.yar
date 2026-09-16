rule TTP_XOR_MULT_DOSStub_5922 {
  strings:
    $key_5922 = { 0d 4a [2] 79 52 [2] 3e 50 [2] 79 41 [2] 37 4d [2] 3b 47 [2] 2c 4c [2] 37 02 [2] 0a }

  condition:
    any of them
}