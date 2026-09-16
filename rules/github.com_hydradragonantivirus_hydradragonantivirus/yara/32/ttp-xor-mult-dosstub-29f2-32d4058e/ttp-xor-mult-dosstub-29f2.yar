rule TTP_XOR_MULT_DOSStub_29f2 {
  strings:
    $key_29f2 = { 7d 9a [2] 09 82 [2] 4e 80 [2] 09 91 [2] 47 9d [2] 4b 97 [2] 5c 9c [2] 47 d2 [2] 7a }

  condition:
    any of them
}