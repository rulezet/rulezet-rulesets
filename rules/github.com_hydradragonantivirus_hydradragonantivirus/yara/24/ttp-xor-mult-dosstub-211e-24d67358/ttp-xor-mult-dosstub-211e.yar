rule TTP_XOR_MULT_DOSStub_211e {
  strings:
    $key_211e = { 75 76 [2] 01 6e [2] 46 6c [2] 01 7d [2] 4f 71 [2] 43 7b [2] 54 70 [2] 4f 3e [2] 72 }

  condition:
    any of them
}