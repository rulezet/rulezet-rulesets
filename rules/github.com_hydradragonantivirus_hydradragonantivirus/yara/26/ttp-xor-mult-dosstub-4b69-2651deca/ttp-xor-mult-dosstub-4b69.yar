rule TTP_XOR_MULT_DOSStub_4b69 {
  strings:
    $key_4b69 = { 1f 01 [2] 6b 19 [2] 2c 1b [2] 6b 0a [2] 25 06 [2] 29 0c [2] 3e 07 [2] 25 49 [2] 18 }

  condition:
    any of them
}