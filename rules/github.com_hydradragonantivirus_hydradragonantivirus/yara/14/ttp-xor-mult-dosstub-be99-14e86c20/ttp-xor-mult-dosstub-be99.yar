rule TTP_XOR_MULT_DOSStub_be99 {
  strings:
    $key_be99 = { ea f1 [2] 9e e9 [2] d9 eb [2] 9e fa [2] d0 f6 [2] dc fc [2] cb f7 [2] d0 b9 [2] ed }

  condition:
    any of them
}