rule TTP_XOR_MULT_DOSStub_0299 {
  strings:
    $key_0299 = { 56 f1 [2] 22 e9 [2] 65 eb [2] 22 fa [2] 6c f6 [2] 60 fc [2] 77 f7 [2] 6c b9 [2] 51 }

  condition:
    any of them
}