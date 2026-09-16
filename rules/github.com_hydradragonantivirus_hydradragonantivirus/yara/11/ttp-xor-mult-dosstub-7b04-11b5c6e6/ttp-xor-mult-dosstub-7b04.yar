rule TTP_XOR_MULT_DOSStub_7b04 {
  strings:
    $key_7b04 = { 2f 6c [2] 5b 74 [2] 1c 76 [2] 5b 67 [2] 15 6b [2] 19 61 [2] 0e 6a [2] 15 24 [2] 28 }

  condition:
    any of them
}