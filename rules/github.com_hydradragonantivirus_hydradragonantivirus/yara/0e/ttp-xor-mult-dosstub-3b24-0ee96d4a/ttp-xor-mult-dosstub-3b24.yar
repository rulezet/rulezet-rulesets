rule TTP_XOR_MULT_DOSStub_3b24 {
  strings:
    $key_3b24 = { 6f 4c [2] 1b 54 [2] 5c 56 [2] 1b 47 [2] 55 4b [2] 59 41 [2] 4e 4a [2] 55 04 [2] 68 }

  condition:
    any of them
}