rule TTP_XOR_MULT_DOSStub_180e {
  strings:
    $key_180e = { 4c 66 [2] 38 7e [2] 7f 7c [2] 38 6d [2] 76 61 [2] 7a 6b [2] 6d 60 [2] 76 2e [2] 4b }

  condition:
    any of them
}