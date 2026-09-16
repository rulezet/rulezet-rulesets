rule TTP_XOR_MULT_DOSStub_7cf2 {
  strings:
    $key_7cf2 = { 28 9a [2] 5c 82 [2] 1b 80 [2] 5c 91 [2] 12 9d [2] 1e 97 [2] 09 9c [2] 12 d2 [2] 2f }

  condition:
    any of them
}