rule TTP_XOR_MULT_DOSStub_79f9 {
  strings:
    $key_79f9 = { 2d 91 [2] 59 89 [2] 1e 8b [2] 59 9a [2] 17 96 [2] 1b 9c [2] 0c 97 [2] 17 d9 [2] 2a }

  condition:
    any of them
}