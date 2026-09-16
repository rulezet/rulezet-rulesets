rule TTP_XOR_MULT_DOSStub_050e {
  strings:
    $key_050e = { 51 66 [2] 25 7e [2] 62 7c [2] 25 6d [2] 6b 61 [2] 67 6b [2] 70 60 [2] 6b 2e [2] 56 }

  condition:
    any of them
}