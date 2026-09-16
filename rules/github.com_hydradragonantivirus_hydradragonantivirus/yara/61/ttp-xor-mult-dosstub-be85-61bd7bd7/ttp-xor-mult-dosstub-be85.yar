rule TTP_XOR_MULT_DOSStub_be85 {
  strings:
    $key_be85 = { ea ed [2] 9e f5 [2] d9 f7 [2] 9e e6 [2] d0 ea [2] dc e0 [2] cb eb [2] d0 a5 [2] ed }

  condition:
    any of them
}