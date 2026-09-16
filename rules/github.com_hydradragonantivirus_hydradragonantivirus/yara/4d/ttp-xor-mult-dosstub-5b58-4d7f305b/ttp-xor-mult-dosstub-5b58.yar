rule TTP_XOR_MULT_DOSStub_5b58 {
  strings:
    $key_5b58 = { 0f 30 [2] 7b 28 [2] 3c 2a [2] 7b 3b [2] 35 37 [2] 39 3d [2] 2e 36 [2] 35 78 [2] 08 }

  condition:
    any of them
}