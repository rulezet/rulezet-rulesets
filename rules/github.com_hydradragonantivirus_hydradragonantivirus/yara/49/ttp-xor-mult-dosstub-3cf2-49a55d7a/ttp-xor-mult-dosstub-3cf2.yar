rule TTP_XOR_MULT_DOSStub_3cf2 {
  strings:
    $key_3cf2 = { 68 9a [2] 1c 82 [2] 5b 80 [2] 1c 91 [2] 52 9d [2] 5e 97 [2] 49 9c [2] 52 d2 [2] 6f }

  condition:
    any of them
}