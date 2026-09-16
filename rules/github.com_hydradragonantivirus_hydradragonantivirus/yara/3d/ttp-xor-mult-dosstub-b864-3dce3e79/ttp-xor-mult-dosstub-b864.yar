rule TTP_XOR_MULT_DOSStub_b864 {
  strings:
    $key_b864 = { ec 0c [2] 98 14 [2] df 16 [2] 98 07 [2] d6 0b [2] da 01 [2] cd 0a [2] d6 44 [2] eb }

  condition:
    any of them
}