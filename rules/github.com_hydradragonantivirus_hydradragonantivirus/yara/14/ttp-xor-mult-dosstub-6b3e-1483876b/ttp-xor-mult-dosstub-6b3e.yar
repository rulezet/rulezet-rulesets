rule TTP_XOR_MULT_DOSStub_6b3e {
  strings:
    $key_6b3e = { 3f 56 [2] 4b 4e [2] 0c 4c [2] 4b 5d [2] 05 51 [2] 09 5b [2] 1e 50 [2] 05 1e [2] 38 }

  condition:
    any of them
}