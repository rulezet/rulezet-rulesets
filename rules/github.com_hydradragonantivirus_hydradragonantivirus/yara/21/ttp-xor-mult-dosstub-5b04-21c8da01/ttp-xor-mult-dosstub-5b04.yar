rule TTP_XOR_MULT_DOSStub_5b04 {
  strings:
    $key_5b04 = { 0f 6c [2] 7b 74 [2] 3c 76 [2] 7b 67 [2] 35 6b [2] 39 61 [2] 2e 6a [2] 35 24 [2] 08 }

  condition:
    any of them
}