rule TTP_XOR_MULT_DOSStub_b83c {
  strings:
    $key_b83c = { ec 54 [2] 98 4c [2] df 4e [2] 98 5f [2] d6 53 [2] da 59 [2] cd 52 [2] d6 1c [2] eb }

  condition:
    any of them
}