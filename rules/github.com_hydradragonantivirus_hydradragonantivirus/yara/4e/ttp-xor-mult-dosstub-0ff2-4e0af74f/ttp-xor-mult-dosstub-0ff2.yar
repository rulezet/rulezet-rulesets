rule TTP_XOR_MULT_DOSStub_0ff2 {
  strings:
    $key_0ff2 = { 5b 9a [2] 2f 82 [2] 68 80 [2] 2f 91 [2] 61 9d [2] 6d 97 [2] 7a 9c [2] 61 d2 [2] 5c }

  condition:
    any of them
}