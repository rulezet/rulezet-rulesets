rule TTP_XOR_MULT_DOSStub_58ed {
  strings:
    $key_58ed = { 0c 85 [2] 78 9d [2] 3f 9f [2] 78 8e [2] 36 82 [2] 3a 88 [2] 2d 83 [2] 36 cd [2] 0b }

  condition:
    any of them
}