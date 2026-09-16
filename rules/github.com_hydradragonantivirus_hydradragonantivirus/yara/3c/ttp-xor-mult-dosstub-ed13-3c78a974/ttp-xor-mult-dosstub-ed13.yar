rule TTP_XOR_MULT_DOSStub_ed13 {
  strings:
    $key_ed13 = { b9 7b [2] cd 63 [2] 8a 61 [2] cd 70 [2] 83 7c [2] 8f 76 [2] 98 7d [2] 83 33 [2] be }

  condition:
    any of them
}