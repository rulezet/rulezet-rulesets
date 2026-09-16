rule TTP_XOR_MULT_DOSStub_edec {
  strings:
    $key_edec = { b9 84 [2] cd 9c [2] 8a 9e [2] cd 8f [2] 83 83 [2] 8f 89 [2] 98 82 [2] 83 cc [2] be }

  condition:
    any of them
}