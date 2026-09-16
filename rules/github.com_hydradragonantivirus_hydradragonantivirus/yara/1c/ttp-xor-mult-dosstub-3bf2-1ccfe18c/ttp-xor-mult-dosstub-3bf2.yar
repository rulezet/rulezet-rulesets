rule TTP_XOR_MULT_DOSStub_3bf2 {
  strings:
    $key_3bf2 = { 6f 9a [2] 1b 82 [2] 5c 80 [2] 1b 91 [2] 55 9d [2] 59 97 [2] 4e 9c [2] 55 d2 [2] 68 }

  condition:
    any of them
}