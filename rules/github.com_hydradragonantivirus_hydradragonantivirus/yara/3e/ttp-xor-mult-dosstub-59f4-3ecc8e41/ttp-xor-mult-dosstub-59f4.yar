rule TTP_XOR_MULT_DOSStub_59f4 {
  strings:
    $key_59f4 = { 0d 9c [2] 79 84 [2] 3e 86 [2] 79 97 [2] 37 9b [2] 3b 91 [2] 2c 9a [2] 37 d4 [2] 0a }

  condition:
    any of them
}