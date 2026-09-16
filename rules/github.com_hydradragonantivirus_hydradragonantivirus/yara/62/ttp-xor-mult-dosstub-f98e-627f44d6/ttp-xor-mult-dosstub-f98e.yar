rule TTP_XOR_MULT_DOSStub_f98e {
  strings:
    $key_f98e = { ad e6 [2] d9 fe [2] 9e fc [2] d9 ed [2] 97 e1 [2] 9b eb [2] 8c e0 [2] 97 ae [2] aa }

  condition:
    any of them
}