rule TTP_XOR_MULT_DOSStub_280e {
  strings:
    $key_280e = { 7c 66 [2] 08 7e [2] 4f 7c [2] 08 6d [2] 46 61 [2] 4a 6b [2] 5d 60 [2] 46 2e [2] 7b }

  condition:
    any of them
}