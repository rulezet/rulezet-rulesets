rule TTP_XOR_MULT_DOSStub_be00 {
  strings:
    $key_be00 = { ea 68 [2] 9e 70 [2] d9 72 [2] 9e 63 [2] d0 6f [2] dc 65 [2] cb 6e [2] d0 20 [2] ed }

  condition:
    any of them
}