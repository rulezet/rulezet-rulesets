rule TTP_XOR_MULT_DOSStub_2b33 {
  strings:
    $key_2b33 = { 7f 5b [2] 0b 43 [2] 4c 41 [2] 0b 50 [2] 45 5c [2] 49 56 [2] 5e 5d [2] 45 13 [2] 78 }

  condition:
    any of them
}