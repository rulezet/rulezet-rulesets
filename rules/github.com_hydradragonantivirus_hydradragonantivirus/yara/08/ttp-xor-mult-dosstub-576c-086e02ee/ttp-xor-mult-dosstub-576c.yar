rule TTP_XOR_MULT_DOSStub_576c {
  strings:
    $key_576c = { 03 04 [2] 77 1c [2] 30 1e [2] 77 0f [2] 39 03 [2] 35 09 [2] 22 02 [2] 39 4c [2] 04 }

  condition:
    any of them
}