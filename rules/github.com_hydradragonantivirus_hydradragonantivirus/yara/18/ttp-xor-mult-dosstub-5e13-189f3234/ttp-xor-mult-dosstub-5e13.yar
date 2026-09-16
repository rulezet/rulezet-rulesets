rule TTP_XOR_MULT_DOSStub_5e13 {
  strings:
    $key_5e13 = { 0a 7b [2] 7e 63 [2] 39 61 [2] 7e 70 [2] 30 7c [2] 3c 76 [2] 2b 7d [2] 30 33 [2] 0d }

  condition:
    any of them
}