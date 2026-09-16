rule TTP_XOR_MULT_DOSStub_0828 {
  strings:
    $key_0828 = { 5c 40 [2] 28 58 [2] 6f 5a [2] 28 4b [2] 66 47 [2] 6a 4d [2] 7d 46 [2] 66 08 [2] 5b }

  condition:
    any of them
}