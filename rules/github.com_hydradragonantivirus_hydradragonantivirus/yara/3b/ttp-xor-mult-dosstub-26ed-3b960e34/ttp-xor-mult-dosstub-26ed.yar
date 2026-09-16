rule TTP_XOR_MULT_DOSStub_26ed {
  strings:
    $key_26ed = { 72 85 [2] 06 9d [2] 41 9f [2] 06 8e [2] 48 82 [2] 44 88 [2] 53 83 [2] 48 cd [2] 75 }

  condition:
    any of them
}