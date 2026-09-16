rule TTP_XOR_MULT_DOSStub_4cf2 {
  strings:
    $key_4cf2 = { 18 9a [2] 6c 82 [2] 2b 80 [2] 6c 91 [2] 22 9d [2] 2e 97 [2] 39 9c [2] 22 d2 [2] 1f }

  condition:
    any of them
}