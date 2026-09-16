rule TTP_XOR_MULT_DOSStub_2ce3 {
  strings:
    $key_2ce3 = { 78 8b [2] 0c 93 [2] 4b 91 [2] 0c 80 [2] 42 8c [2] 4e 86 [2] 59 8d [2] 42 c3 [2] 7f }

  condition:
    any of them
}