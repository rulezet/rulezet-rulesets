rule TTP_XOR_MULT_DOSStub_6b0e {
  strings:
    $key_6b0e = { 3f 66 [2] 4b 7e [2] 0c 7c [2] 4b 6d [2] 05 61 [2] 09 6b [2] 1e 60 [2] 05 2e [2] 38 }

  condition:
    any of them
}