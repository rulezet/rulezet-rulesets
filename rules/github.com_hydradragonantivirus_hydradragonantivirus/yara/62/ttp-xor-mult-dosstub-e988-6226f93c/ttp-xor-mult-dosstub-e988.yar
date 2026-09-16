rule TTP_XOR_MULT_DOSStub_e988 {
  strings:
    $key_e988 = { bd e0 [2] c9 f8 [2] 8e fa [2] c9 eb [2] 87 e7 [2] 8b ed [2] 9c e6 [2] 87 a8 [2] ba }

  condition:
    any of them
}