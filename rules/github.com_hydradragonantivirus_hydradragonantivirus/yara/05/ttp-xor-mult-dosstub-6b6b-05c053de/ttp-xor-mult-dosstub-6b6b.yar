rule TTP_XOR_MULT_DOSStub_6b6b {
  strings:
    $key_6b6b = { 3f 03 [2] 4b 1b [2] 0c 19 [2] 4b 08 [2] 05 04 [2] 09 0e [2] 1e 05 [2] 05 4b [2] 38 }

  condition:
    any of them
}