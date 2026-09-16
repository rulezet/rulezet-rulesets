rule TTP_XOR_MULT_DOSStub_326c {
  strings:
    $key_326c = { 66 04 [2] 12 1c [2] 55 1e [2] 12 0f [2] 5c 03 [2] 50 09 [2] 47 02 [2] 5c 4c [2] 61 }

  condition:
    any of them
}