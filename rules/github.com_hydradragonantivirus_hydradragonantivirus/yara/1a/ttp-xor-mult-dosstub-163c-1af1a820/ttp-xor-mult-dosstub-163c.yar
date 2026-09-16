rule TTP_XOR_MULT_DOSStub_163c {
  strings:
    $key_163c = { 42 54 [2] 36 4c [2] 71 4e [2] 36 5f [2] 78 53 [2] 74 59 [2] 63 52 [2] 78 1c [2] 45 }

  condition:
    any of them
}