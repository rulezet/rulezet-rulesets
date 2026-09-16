rule TTP_XOR_MULT_DOSStub_2f99 {
  strings:
    $key_2f99 = { 7b f1 [2] 0f e9 [2] 48 eb [2] 0f fa [2] 41 f6 [2] 4d fc [2] 5a f7 [2] 41 b9 [2] 7c }

  condition:
    any of them
}