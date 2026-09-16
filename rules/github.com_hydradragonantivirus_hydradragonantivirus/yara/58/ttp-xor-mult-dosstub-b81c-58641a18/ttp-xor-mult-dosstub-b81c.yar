rule TTP_XOR_MULT_DOSStub_b81c {
  strings:
    $key_b81c = { ec 74 [2] 98 6c [2] df 6e [2] 98 7f [2] d6 73 [2] da 79 [2] cd 72 [2] d6 3c [2] eb }

  condition:
    any of them
}