rule TTP_XOR_MULT_DOSStub_ed30 {
  strings:
    $key_ed30 = { b9 58 [2] cd 40 [2] 8a 42 [2] cd 53 [2] 83 5f [2] 8f 55 [2] 98 5e [2] 83 10 [2] be }

  condition:
    any of them
}