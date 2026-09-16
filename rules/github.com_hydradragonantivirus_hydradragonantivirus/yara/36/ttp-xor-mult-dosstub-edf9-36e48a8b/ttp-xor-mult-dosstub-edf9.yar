rule TTP_XOR_MULT_DOSStub_edf9 {
  strings:
    $key_edf9 = { b9 91 [2] cd 89 [2] 8a 8b [2] cd 9a [2] 83 96 [2] 8f 9c [2] 98 97 [2] 83 d9 [2] be }

  condition:
    any of them
}