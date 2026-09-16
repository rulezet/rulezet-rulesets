rule TTP_XOR_MULT_DOSStub_3b69 {
  strings:
    $key_3b69 = { 6f 01 [2] 1b 19 [2] 5c 1b [2] 1b 0a [2] 55 06 [2] 59 0c [2] 4e 07 [2] 55 49 [2] 68 }

  condition:
    any of them
}