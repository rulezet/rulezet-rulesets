rule TTP_XOR_MULT_DOSStub_271e {
  strings:
    $key_271e = { 73 76 [2] 07 6e [2] 40 6c [2] 07 7d [2] 49 71 [2] 45 7b [2] 52 70 [2] 49 3e [2] 74 }

  condition:
    any of them
}