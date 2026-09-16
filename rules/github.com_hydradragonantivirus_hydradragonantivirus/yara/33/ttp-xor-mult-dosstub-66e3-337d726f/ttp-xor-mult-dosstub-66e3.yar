rule TTP_XOR_MULT_DOSStub_66e3 {
  strings:
    $key_66e3 = { 32 8b [2] 46 93 [2] 01 91 [2] 46 80 [2] 08 8c [2] 04 86 [2] 13 8d [2] 08 c3 [2] 35 }

  condition:
    any of them
}