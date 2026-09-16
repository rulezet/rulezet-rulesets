rule TTP_XOR_MULT_DOSStub_29f4 {
  strings:
    $key_29f4 = { 7d 9c [2] 09 84 [2] 4e 86 [2] 09 97 [2] 47 9b [2] 4b 91 [2] 5c 9a [2] 47 d4 [2] 7a }

  condition:
    any of them
}