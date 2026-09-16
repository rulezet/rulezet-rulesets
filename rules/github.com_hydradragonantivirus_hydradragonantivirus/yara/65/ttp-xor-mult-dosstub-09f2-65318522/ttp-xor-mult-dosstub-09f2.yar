rule TTP_XOR_MULT_DOSStub_09f2 {
  strings:
    $key_09f2 = { 5d 9a [2] 29 82 [2] 6e 80 [2] 29 91 [2] 67 9d [2] 6b 97 [2] 7c 9c [2] 67 d2 [2] 5a }

  condition:
    any of them
}