rule TTP_XOR_MULT_DOSStub_ea99 {
  strings:
    $key_ea99 = { be f1 [2] ca e9 [2] 8d eb [2] ca fa [2] 84 f6 [2] 88 fc [2] 9f f7 [2] 84 b9 [2] b9 }

  condition:
    any of them
}