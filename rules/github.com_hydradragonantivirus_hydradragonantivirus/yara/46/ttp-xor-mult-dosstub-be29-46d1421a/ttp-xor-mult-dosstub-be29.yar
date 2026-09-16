rule TTP_XOR_MULT_DOSStub_be29 {
  strings:
    $key_be29 = { ea 41 [2] 9e 59 [2] d9 5b [2] 9e 4a [2] d0 46 [2] dc 4c [2] cb 47 [2] d0 09 [2] ed }

  condition:
    any of them
}