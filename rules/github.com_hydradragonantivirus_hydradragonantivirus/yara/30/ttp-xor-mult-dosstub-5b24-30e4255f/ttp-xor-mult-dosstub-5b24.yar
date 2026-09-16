rule TTP_XOR_MULT_DOSStub_5b24 {
  strings:
    $key_5b24 = { 0f 4c [2] 7b 54 [2] 3c 56 [2] 7b 47 [2] 35 4b [2] 39 41 [2] 2e 4a [2] 35 04 [2] 08 }

  condition:
    any of them
}