rule TTP_XOR_MULT_DOSStub_6ae3 {
  strings:
    $key_6ae3 = { 3e 8b [2] 4a 93 [2] 0d 91 [2] 4a 80 [2] 04 8c [2] 08 86 [2] 1f 8d [2] 04 c3 [2] 39 }

  condition:
    any of them
}