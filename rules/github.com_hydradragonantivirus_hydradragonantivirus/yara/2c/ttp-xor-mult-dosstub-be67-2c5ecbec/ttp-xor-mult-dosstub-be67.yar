rule TTP_XOR_MULT_DOSStub_be67 {
  strings:
    $key_be67 = { ea 0f [2] 9e 17 [2] d9 15 [2] 9e 04 [2] d0 08 [2] dc 02 [2] cb 09 [2] d0 47 [2] ed }

  condition:
    any of them
}