rule TTP_XOR_MULT_DOSStub_0628 {
  strings:
    $key_0628 = { 52 40 [2] 26 58 [2] 61 5a [2] 26 4b [2] 68 47 [2] 64 4d [2] 73 46 [2] 68 08 [2] 55 }

  condition:
    any of them
}