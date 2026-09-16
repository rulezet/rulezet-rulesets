rule TTP_XOR_MULT_DOSStub_391e {
  strings:
    $key_391e = { 6d 76 [2] 19 6e [2] 5e 6c [2] 19 7d [2] 57 71 [2] 5b 7b [2] 4c 70 [2] 57 3e [2] 6a }

  condition:
    any of them
}