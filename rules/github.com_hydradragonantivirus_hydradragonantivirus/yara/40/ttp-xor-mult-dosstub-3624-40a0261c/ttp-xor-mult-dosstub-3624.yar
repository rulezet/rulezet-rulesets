rule TTP_XOR_MULT_DOSStub_3624 {
  strings:
    $key_3624 = { 62 4c [2] 16 54 [2] 51 56 [2] 16 47 [2] 58 4b [2] 54 41 [2] 43 4a [2] 58 04 [2] 65 }

  condition:
    any of them
}