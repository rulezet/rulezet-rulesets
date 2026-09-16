rule TTP_XOR_MULT_DOSStub_21e3 {
  strings:
    $key_21e3 = { 75 8b [2] 01 93 [2] 46 91 [2] 01 80 [2] 4f 8c [2] 43 86 [2] 54 8d [2] 4f c3 [2] 72 }

  condition:
    any of them
}