rule TTP_XOR_MULT_DOSStub_b873 {
  strings:
    $key_b873 = { ec 1b [2] 98 03 [2] df 01 [2] 98 10 [2] d6 1c [2] da 16 [2] cd 1d [2] d6 53 [2] eb }

  condition:
    any of them
}