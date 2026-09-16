rule TTP_XOR_MULT_DOSStub_2b6b {
  strings:
    $key_2b6b = { 7f 03 [2] 0b 1b [2] 4c 19 [2] 0b 08 [2] 45 04 [2] 49 0e [2] 5e 05 [2] 45 4b [2] 78 }

  condition:
    any of them
}