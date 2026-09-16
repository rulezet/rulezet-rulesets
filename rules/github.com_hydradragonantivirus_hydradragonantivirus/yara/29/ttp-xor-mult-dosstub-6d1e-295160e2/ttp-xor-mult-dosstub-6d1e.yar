rule TTP_XOR_MULT_DOSStub_6d1e {
  strings:
    $key_6d1e = { 39 76 [2] 4d 6e [2] 0a 6c [2] 4d 7d [2] 03 71 [2] 0f 7b [2] 18 70 [2] 03 3e [2] 3e }

  condition:
    any of them
}