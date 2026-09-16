rule TTP_XOR_MULT_DOSStub_5b35 {
  strings:
    $key_5b35 = { 0f 5d [2] 7b 45 [2] 3c 47 [2] 7b 56 [2] 35 5a [2] 39 50 [2] 2e 5b [2] 35 15 [2] 08 }

  condition:
    any of them
}