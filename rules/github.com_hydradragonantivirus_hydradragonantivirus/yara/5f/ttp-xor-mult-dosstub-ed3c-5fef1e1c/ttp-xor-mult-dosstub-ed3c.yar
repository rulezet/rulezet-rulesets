rule TTP_XOR_MULT_DOSStub_ed3c {
  strings:
    $key_ed3c = { b9 54 [2] cd 4c [2] 8a 4e [2] cd 5f [2] 83 53 [2] 8f 59 [2] 98 52 [2] 83 1c [2] be }

  condition:
    any of them
}