rule TTP_XOR_MULT_DOSStub_6ded {
  strings:
    $key_6ded = { 39 85 [2] 4d 9d [2] 0a 9f [2] 4d 8e [2] 03 82 [2] 0f 88 [2] 18 83 [2] 03 cd [2] 3e }

  condition:
    any of them
}