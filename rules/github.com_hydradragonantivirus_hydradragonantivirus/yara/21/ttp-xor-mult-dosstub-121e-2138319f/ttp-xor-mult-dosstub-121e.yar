rule TTP_XOR_MULT_DOSStub_121e {
  strings:
    $key_121e = { 46 76 [2] 32 6e [2] 75 6c [2] 32 7d [2] 7c 71 [2] 70 7b [2] 67 70 [2] 7c 3e [2] 41 }

  condition:
    any of them
}