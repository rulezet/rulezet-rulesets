rule TTP_XOR_MULT_DOSStub_3b33 {
  strings:
    $key_3b33 = { 6f 5b [2] 1b 43 [2] 5c 41 [2] 1b 50 [2] 55 5c [2] 59 56 [2] 4e 5d [2] 55 13 [2] 68 }

  condition:
    any of them
}