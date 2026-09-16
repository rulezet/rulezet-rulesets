rule TTP_XOR_MULT_DOSStub_2f1e {
  strings:
    $key_2f1e = { 7b 76 [2] 0f 6e [2] 48 6c [2] 0f 7d [2] 41 71 [2] 4d 7b [2] 5a 70 [2] 41 3e [2] 7c }

  condition:
    any of them
}