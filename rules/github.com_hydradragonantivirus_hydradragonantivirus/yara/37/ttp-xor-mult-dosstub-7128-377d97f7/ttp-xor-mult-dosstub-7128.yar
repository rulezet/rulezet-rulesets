rule TTP_XOR_MULT_DOSStub_7128 {
  strings:
    $key_7128 = { 25 40 [2] 51 58 [2] 16 5a [2] 51 4b [2] 1f 47 [2] 13 4d [2] 04 46 [2] 1f 08 [2] 22 }

  condition:
    any of them
}