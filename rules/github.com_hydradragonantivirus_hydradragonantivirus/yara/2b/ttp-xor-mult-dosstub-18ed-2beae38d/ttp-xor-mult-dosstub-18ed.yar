rule TTP_XOR_MULT_DOSStub_18ed {
  strings:
    $key_18ed = { 4c 85 [2] 38 9d [2] 7f 9f [2] 38 8e [2] 76 82 [2] 7a 88 [2] 6d 83 [2] 76 cd [2] 4b }

  condition:
    any of them
}