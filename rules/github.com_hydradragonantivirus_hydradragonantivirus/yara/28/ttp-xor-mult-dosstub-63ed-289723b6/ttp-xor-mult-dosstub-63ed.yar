rule TTP_XOR_MULT_DOSStub_63ed {
  strings:
    $key_63ed = { 37 85 [2] 43 9d [2] 04 9f [2] 43 8e [2] 0d 82 [2] 01 88 [2] 16 83 [2] 0d cd [2] 30 }

  condition:
    any of them
}