rule TTP_XOR_MULT_DOSStub_5719 {
  strings:
    $key_5719 = { 03 71 [2] 77 69 [2] 30 6b [2] 77 7a [2] 39 76 [2] 35 7c [2] 22 77 [2] 39 39 [2] 04 }

  condition:
    any of them
}