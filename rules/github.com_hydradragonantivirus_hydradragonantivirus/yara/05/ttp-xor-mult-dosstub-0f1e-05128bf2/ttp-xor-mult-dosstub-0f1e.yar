rule TTP_XOR_MULT_DOSStub_0f1e {
  strings:
    $key_0f1e = { 5b 76 [2] 2f 6e [2] 68 6c [2] 2f 7d [2] 61 71 [2] 6d 7b [2] 7a 70 [2] 61 3e [2] 5c }

  condition:
    any of them
}