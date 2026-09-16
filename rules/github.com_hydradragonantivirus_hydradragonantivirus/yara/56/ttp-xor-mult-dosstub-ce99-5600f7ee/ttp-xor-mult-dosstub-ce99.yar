rule TTP_XOR_MULT_DOSStub_ce99 {
  strings:
    $key_ce99 = { 9a f1 [2] ee e9 [2] a9 eb [2] ee fa [2] a0 f6 [2] ac fc [2] bb f7 [2] a0 b9 [2] 9d }

  condition:
    any of them
}