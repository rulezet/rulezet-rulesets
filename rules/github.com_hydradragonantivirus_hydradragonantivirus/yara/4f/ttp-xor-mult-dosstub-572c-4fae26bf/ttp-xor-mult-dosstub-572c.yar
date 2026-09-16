rule TTP_XOR_MULT_DOSStub_572c {
  strings:
    $key_572c = { 03 44 [2] 77 5c [2] 30 5e [2] 77 4f [2] 39 43 [2] 35 49 [2] 22 42 [2] 39 0c [2] 04 }

  condition:
    any of them
}