rule TTP_XOR_MULT_DOSStub_0ef4 {
  strings:
    $key_0ef4 = { 5a 9c [2] 2e 84 [2] 69 86 [2] 2e 97 [2] 60 9b [2] 6c 91 [2] 7b 9a [2] 60 d4 [2] 5d }

  condition:
    any of them
}