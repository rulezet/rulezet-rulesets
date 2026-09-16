rule TTP_XOR_MULT_DOSStub_0913 {
  strings:
    $key_0913 = { 5d 7b [2] 29 63 [2] 6e 61 [2] 29 70 [2] 67 7c [2] 6b 76 [2] 7c 7d [2] 67 33 [2] 5a }

  condition:
    any of them
}