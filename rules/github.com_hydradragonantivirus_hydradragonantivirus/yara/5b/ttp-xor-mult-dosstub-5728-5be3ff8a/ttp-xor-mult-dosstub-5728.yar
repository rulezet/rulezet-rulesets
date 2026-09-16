rule TTP_XOR_MULT_DOSStub_5728 {
  strings:
    $key_5728 = { 03 40 [2] 77 58 [2] 30 5a [2] 77 4b [2] 39 47 [2] 35 4d [2] 22 46 [2] 39 08 [2] 04 }

  condition:
    any of them
}