rule TTP_XOR_MULT_DOSStub_5ef4 {
  strings:
    $key_5ef4 = { 0a 9c [2] 7e 84 [2] 39 86 [2] 7e 97 [2] 30 9b [2] 3c 91 [2] 2b 9a [2] 30 d4 [2] 0d }

  condition:
    any of them
}