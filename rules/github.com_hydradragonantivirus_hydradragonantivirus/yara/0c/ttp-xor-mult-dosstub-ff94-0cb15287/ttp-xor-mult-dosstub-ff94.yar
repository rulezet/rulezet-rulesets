rule TTP_XOR_MULT_DOSStub_ff94 {
  strings:
    $key_ff94 = { ab fc [2] df e4 [2] 98 e6 [2] df f7 [2] 91 fb [2] 9d f1 [2] 8a fa [2] 91 b4 [2] ac }

  condition:
    any of them
}