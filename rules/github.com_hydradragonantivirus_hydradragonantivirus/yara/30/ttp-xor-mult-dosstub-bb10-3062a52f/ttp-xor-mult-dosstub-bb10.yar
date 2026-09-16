rule TTP_XOR_MULT_DOSStub_bb10 {
  strings:
    $key_bb10 = { ef 78 [2] 9b 60 [2] dc 62 [2] 9b 73 [2] d5 7f [2] d9 75 [2] ce 7e [2] d5 30 [2] e8 }

  condition:
    any of them
}