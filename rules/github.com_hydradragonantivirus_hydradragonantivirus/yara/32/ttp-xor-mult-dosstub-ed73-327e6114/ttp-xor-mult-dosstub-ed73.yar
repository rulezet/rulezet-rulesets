rule TTP_XOR_MULT_DOSStub_ed73 {
  strings:
    $key_ed73 = { b9 1b [2] cd 03 [2] 8a 01 [2] cd 10 [2] 83 1c [2] 8f 16 [2] 98 1d [2] 83 53 [2] be }

  condition:
    any of them
}