rule TTP_XOR_MULT_DOSStub_6a35 {
  strings:
    $key_6a35 = { 3e 5d [2] 4a 45 [2] 0d 47 [2] 4a 56 [2] 04 5a [2] 08 50 [2] 1f 5b [2] 04 15 [2] 39 }

  condition:
    any of them
}