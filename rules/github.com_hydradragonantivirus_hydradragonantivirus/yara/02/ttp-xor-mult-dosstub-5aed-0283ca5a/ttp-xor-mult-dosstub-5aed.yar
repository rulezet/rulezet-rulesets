rule TTP_XOR_MULT_DOSStub_5aed {
  strings:
    $key_5aed = { 0e 85 [2] 7a 9d [2] 3d 9f [2] 7a 8e [2] 34 82 [2] 38 88 [2] 2f 83 [2] 34 cd [2] 09 }

  condition:
    any of them
}