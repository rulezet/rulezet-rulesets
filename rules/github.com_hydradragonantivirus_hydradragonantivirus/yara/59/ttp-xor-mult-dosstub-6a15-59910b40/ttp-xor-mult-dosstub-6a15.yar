rule TTP_XOR_MULT_DOSStub_6a15 {
  strings:
    $key_6a15 = { 3e 7d [2] 4a 65 [2] 0d 67 [2] 4a 76 [2] 04 7a [2] 08 70 [2] 1f 7b [2] 04 35 [2] 39 }

  condition:
    any of them
}