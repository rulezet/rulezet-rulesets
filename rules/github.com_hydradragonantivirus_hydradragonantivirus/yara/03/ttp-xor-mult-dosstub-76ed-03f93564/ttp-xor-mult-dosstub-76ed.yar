rule TTP_XOR_MULT_DOSStub_76ed {
  strings:
    $key_76ed = { 22 85 [2] 56 9d [2] 11 9f [2] 56 8e [2] 18 82 [2] 14 88 [2] 03 83 [2] 18 cd [2] 25 }

  condition:
    any of them
}