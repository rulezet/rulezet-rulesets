rule TTP_XOR_MULT_DOSStub_b8fe {
  strings:
    $key_b8fe = { ec 96 [2] 98 8e [2] df 8c [2] 98 9d [2] d6 91 [2] da 9b [2] cd 90 [2] d6 de [2] eb }

  condition:
    any of them
}