rule TTP_XOR_MULT_DOSStub_142a {
  strings:
    $key_142a = { 40 42 [2] 34 5a [2] 73 58 [2] 34 49 [2] 7a 45 [2] 76 4f [2] 61 44 [2] 7a 0a [2] 47 }

  condition:
    any of them
}