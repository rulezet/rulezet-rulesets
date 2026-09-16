rule TTP_XOR_MULT_DOSStub_475b {
  strings:
    $key_475b = { 13 33 [2] 67 2b [2] 20 29 [2] 67 38 [2] 29 34 [2] 25 3e [2] 32 35 [2] 29 7b [2] 14 }

  condition:
    any of them
}