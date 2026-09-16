rule TTP_XOR_MULT_DOSStub_5ded {
  strings:
    $key_5ded = { 09 85 [2] 7d 9d [2] 3a 9f [2] 7d 8e [2] 33 82 [2] 3f 88 [2] 28 83 [2] 33 cd [2] 0e }

  condition:
    any of them
}