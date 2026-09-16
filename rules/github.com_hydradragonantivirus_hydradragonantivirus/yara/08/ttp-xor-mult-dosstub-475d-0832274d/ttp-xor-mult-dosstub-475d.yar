rule TTP_XOR_MULT_DOSStub_475d {
  strings:
    $key_475d = { 13 35 [2] 67 2d [2] 20 2f [2] 67 3e [2] 29 32 [2] 25 38 [2] 32 33 [2] 29 7d [2] 14 }

  condition:
    any of them
}