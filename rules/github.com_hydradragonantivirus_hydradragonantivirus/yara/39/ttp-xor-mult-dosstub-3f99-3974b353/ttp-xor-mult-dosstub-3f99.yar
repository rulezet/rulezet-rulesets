rule TTP_XOR_MULT_DOSStub_3f99 {
  strings:
    $key_3f99 = { 6b f1 [2] 1f e9 [2] 58 eb [2] 1f fa [2] 51 f6 [2] 5d fc [2] 4a f7 [2] 51 b9 [2] 6c }

  condition:
    any of them
}