rule TTP_XOR_MULT_DOSStub_bef9 {
  strings:
    $key_bef9 = { ea 91 [2] 9e 89 [2] d9 8b [2] 9e 9a [2] d0 96 [2] dc 9c [2] cb 97 [2] d0 d9 [2] ed }

  condition:
    any of them
}