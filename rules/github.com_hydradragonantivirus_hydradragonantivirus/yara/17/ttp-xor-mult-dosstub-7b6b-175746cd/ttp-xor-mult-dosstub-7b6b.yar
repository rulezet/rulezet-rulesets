rule TTP_XOR_MULT_DOSStub_7b6b {
  strings:
    $key_7b6b = { 2f 03 [2] 5b 1b [2] 1c 19 [2] 5b 08 [2] 15 04 [2] 19 0e [2] 0e 05 [2] 15 4b [2] 28 }

  condition:
    any of them
}