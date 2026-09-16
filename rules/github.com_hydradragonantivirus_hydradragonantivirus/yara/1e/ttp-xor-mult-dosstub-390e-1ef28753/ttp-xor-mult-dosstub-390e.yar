rule TTP_XOR_MULT_DOSStub_390e {
  strings:
    $key_390e = { 6d 66 [2] 19 7e [2] 5e 7c [2] 19 6d [2] 57 61 [2] 5b 6b [2] 4c 60 [2] 57 2e [2] 6a }

  condition:
    any of them
}