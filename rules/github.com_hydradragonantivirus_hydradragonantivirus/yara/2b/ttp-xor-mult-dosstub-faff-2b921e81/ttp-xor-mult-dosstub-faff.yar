rule TTP_XOR_MULT_DOSStub_faff {
  strings:
    $key_faff = { ae 97 [2] da 8f [2] 9d 8d [2] da 9c [2] 94 90 [2] 98 9a [2] 8f 91 [2] 94 df [2] a9 }

  condition:
    any of them
}