rule TTP_XOR_MULT_DOSStub_6f1e {
  strings:
    $key_6f1e = { 3b 76 [2] 4f 6e [2] 08 6c [2] 4f 7d [2] 01 71 [2] 0d 7b [2] 1a 70 [2] 01 3e [2] 3c }

  condition:
    any of them
}