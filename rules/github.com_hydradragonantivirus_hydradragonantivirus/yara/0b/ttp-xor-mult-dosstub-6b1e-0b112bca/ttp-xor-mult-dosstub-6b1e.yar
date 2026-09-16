rule TTP_XOR_MULT_DOSStub_6b1e {
  strings:
    $key_6b1e = { 3f 76 [2] 4b 6e [2] 0c 6c [2] 4b 7d [2] 05 71 [2] 09 7b [2] 1e 70 [2] 05 3e [2] 38 }

  condition:
    any of them
}