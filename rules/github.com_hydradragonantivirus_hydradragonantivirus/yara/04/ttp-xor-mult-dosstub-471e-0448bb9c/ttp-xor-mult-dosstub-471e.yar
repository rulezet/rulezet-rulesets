rule TTP_XOR_MULT_DOSStub_471e {
  strings:
    $key_471e = { 13 76 [2] 67 6e [2] 20 6c [2] 67 7d [2] 29 71 [2] 25 7b [2] 32 70 [2] 29 3e [2] 14 }

  condition:
    any of them
}