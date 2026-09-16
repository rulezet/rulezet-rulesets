rule TTP_XOR_MULT_DOSStub_111e {
  strings:
    $key_111e = { 45 76 [2] 31 6e [2] 76 6c [2] 31 7d [2] 7f 71 [2] 73 7b [2] 64 70 [2] 7f 3e [2] 42 }

  condition:
    any of them
}