rule TTP_XOR_MULT_DOSStub_456c {
  strings:
    $key_456c = { 11 04 [2] 65 1c [2] 22 1e [2] 65 0f [2] 2b 03 [2] 27 09 [2] 30 02 [2] 2b 4c [2] 16 }

  condition:
    any of them
}