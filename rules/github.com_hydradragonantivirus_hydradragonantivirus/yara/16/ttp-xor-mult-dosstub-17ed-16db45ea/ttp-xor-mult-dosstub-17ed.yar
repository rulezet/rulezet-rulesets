rule TTP_XOR_MULT_DOSStub_17ed {
  strings:
    $key_17ed = { 43 85 [2] 37 9d [2] 70 9f [2] 37 8e [2] 79 82 [2] 75 88 [2] 62 83 [2] 79 cd [2] 44 }

  condition:
    any of them
}