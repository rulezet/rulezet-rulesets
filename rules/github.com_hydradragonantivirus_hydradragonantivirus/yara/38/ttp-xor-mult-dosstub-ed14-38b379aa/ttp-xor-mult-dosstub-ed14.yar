rule TTP_XOR_MULT_DOSStub_ed14 {
  strings:
    $key_ed14 = { b9 7c [2] cd 64 [2] 8a 66 [2] cd 77 [2] 83 7b [2] 8f 71 [2] 98 7a [2] 83 34 [2] be }

  condition:
    any of them
}