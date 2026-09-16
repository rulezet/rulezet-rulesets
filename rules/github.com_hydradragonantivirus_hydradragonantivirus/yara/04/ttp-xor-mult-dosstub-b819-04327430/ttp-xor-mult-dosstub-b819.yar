rule TTP_XOR_MULT_DOSStub_b819 {
  strings:
    $key_b819 = { ec 71 [2] 98 69 [2] df 6b [2] 98 7a [2] d6 76 [2] da 7c [2] cd 77 [2] d6 39 [2] eb }

  condition:
    any of them
}