rule TTP_XOR_MULT_DOSStub_3b35 {
  strings:
    $key_3b35 = { 6f 5d [2] 1b 45 [2] 5c 47 [2] 1b 56 [2] 55 5a [2] 59 50 [2] 4e 5b [2] 55 15 [2] 68 }

  condition:
    any of them
}