rule TTP_XOR_MULT_DOSStub_681e {
  strings:
    $key_681e = { 3c 76 [2] 48 6e [2] 0f 6c [2] 48 7d [2] 06 71 [2] 0a 7b [2] 1d 70 [2] 06 3e [2] 3b }

  condition:
    any of them
}