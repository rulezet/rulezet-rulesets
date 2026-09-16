rule TTP_XOR_MULT_DOSStub_3ded {
  strings:
    $key_3ded = { 69 85 [2] 1d 9d [2] 5a 9f [2] 1d 8e [2] 53 82 [2] 5f 88 [2] 48 83 [2] 53 cd [2] 6e }

  condition:
    any of them
}