rule TTP_XOR_MULT_DOSStub_636c {
  strings:
    $key_636c = { 37 04 [2] 43 1c [2] 04 1e [2] 43 0f [2] 0d 03 [2] 01 09 [2] 16 02 [2] 0d 4c [2] 30 }

  condition:
    any of them
}