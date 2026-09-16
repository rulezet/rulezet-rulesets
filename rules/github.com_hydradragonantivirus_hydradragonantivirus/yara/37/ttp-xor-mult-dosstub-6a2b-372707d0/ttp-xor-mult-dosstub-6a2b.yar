rule TTP_XOR_MULT_DOSStub_6a2b {
  strings:
    $key_6a2b = { 3e 43 [2] 4a 5b [2] 0d 59 [2] 4a 48 [2] 04 44 [2] 08 4e [2] 1f 45 [2] 04 0b [2] 39 }

  condition:
    any of them
}