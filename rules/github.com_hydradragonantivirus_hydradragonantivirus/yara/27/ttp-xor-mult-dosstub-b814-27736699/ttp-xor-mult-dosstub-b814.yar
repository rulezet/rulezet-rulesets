rule TTP_XOR_MULT_DOSStub_b814 {
  strings:
    $key_b814 = { ec 7c [2] 98 64 [2] df 66 [2] 98 77 [2] d6 7b [2] da 71 [2] cd 7a [2] d6 34 [2] eb }

  condition:
    any of them
}