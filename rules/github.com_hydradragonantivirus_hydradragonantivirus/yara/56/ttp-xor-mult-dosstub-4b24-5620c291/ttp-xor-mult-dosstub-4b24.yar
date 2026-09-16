rule TTP_XOR_MULT_DOSStub_4b24 {
  strings:
    $key_4b24 = { 1f 4c [2] 6b 54 [2] 2c 56 [2] 6b 47 [2] 25 4b [2] 29 41 [2] 3e 4a [2] 25 04 [2] 18 }

  condition:
    any of them
}