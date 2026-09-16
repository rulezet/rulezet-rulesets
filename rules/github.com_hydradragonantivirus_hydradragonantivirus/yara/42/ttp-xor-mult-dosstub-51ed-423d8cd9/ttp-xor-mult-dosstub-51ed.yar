rule TTP_XOR_MULT_DOSStub_51ed {
  strings:
    $key_51ed = { 05 85 [2] 71 9d [2] 36 9f [2] 71 8e [2] 3f 82 [2] 33 88 [2] 24 83 [2] 3f cd [2] 02 }

  condition:
    any of them
}