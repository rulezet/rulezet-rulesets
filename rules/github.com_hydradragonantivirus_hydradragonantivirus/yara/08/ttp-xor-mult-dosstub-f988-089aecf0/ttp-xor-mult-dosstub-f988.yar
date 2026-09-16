rule TTP_XOR_MULT_DOSStub_f988 {
  strings:
    $key_f988 = { ad e0 [2] d9 f8 [2] 9e fa [2] d9 eb [2] 97 e7 [2] 9b ed [2] 8c e6 [2] 97 a8 [2] aa }

  condition:
    any of them
}