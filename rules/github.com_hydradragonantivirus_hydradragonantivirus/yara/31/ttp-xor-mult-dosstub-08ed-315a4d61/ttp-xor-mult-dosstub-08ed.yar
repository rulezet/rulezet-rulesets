rule TTP_XOR_MULT_DOSStub_08ed {
  strings:
    $key_08ed = { 5c 85 [2] 28 9d [2] 6f 9f [2] 28 8e [2] 66 82 [2] 6a 88 [2] 7d 83 [2] 66 cd [2] 5b }

  condition:
    any of them
}