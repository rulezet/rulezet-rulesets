rule TTP_XOR_MULT_DOSStub_f98f {
  strings:
    $key_f98f = { ad e7 [2] d9 ff [2] 9e fd [2] d9 ec [2] 97 e0 [2] 9b ea [2] 8c e1 [2] 97 af [2] aa }

  condition:
    any of them
}