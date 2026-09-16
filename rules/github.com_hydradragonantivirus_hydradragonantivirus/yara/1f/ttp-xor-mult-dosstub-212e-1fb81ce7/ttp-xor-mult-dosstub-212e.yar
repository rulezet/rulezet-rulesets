rule TTP_XOR_MULT_DOSStub_212e {
  strings:
    $key_212e = { 75 46 [2] 01 5e [2] 46 5c [2] 01 4d [2] 4f 41 [2] 43 4b [2] 54 40 [2] 4f 0e [2] 72 }

  condition:
    any of them
}