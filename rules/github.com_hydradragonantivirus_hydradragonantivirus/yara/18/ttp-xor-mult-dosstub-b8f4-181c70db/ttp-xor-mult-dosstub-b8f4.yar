rule TTP_XOR_MULT_DOSStub_b8f4 {
  strings:
    $key_b8f4 = { ec 9c [2] 98 84 [2] df 86 [2] 98 97 [2] d6 9b [2] da 91 [2] cd 9a [2] d6 d4 [2] eb }

  condition:
    any of them
}