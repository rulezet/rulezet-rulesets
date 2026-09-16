rule TTP_XOR_MULT_DOSStub_046c {
  strings:
    $key_046c = { 50 04 [2] 24 1c [2] 63 1e [2] 24 0f [2] 6a 03 [2] 66 09 [2] 71 02 [2] 6a 4c [2] 57 }

  condition:
    any of them
}