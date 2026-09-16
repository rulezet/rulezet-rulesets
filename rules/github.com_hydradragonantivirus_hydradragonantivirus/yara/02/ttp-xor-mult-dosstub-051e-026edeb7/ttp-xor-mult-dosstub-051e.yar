rule TTP_XOR_MULT_DOSStub_051e {
  strings:
    $key_051e = { 51 76 [2] 25 6e [2] 62 6c [2] 25 7d [2] 6b 71 [2] 67 7b [2] 70 70 [2] 6b 3e [2] 56 }

  condition:
    any of them
}