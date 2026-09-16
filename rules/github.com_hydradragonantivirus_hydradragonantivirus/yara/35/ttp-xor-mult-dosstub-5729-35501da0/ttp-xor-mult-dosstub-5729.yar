rule TTP_XOR_MULT_DOSStub_5729 {
  strings:
    $key_5729 = { 03 41 [2] 77 59 [2] 30 5b [2] 77 4a [2] 39 46 [2] 35 4c [2] 22 47 [2] 39 09 [2] 04 }

  condition:
    any of them
}