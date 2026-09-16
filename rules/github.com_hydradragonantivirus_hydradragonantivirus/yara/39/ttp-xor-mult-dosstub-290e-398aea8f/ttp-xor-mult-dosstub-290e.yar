rule TTP_XOR_MULT_DOSStub_290e {
  strings:
    $key_290e = { 7d 66 [2] 09 7e [2] 4e 7c [2] 09 6d [2] 47 61 [2] 4b 6b [2] 5c 60 [2] 47 2e [2] 7a }

  condition:
    any of them
}