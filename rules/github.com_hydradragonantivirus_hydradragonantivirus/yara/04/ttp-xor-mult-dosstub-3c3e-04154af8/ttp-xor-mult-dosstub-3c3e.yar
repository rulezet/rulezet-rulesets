rule TTP_XOR_MULT_DOSStub_3c3e {
  strings:
    $key_3c3e = { 68 56 [2] 1c 4e [2] 5b 4c [2] 1c 5d [2] 52 51 [2] 5e 5b [2] 49 50 [2] 52 1e [2] 6f }

  condition:
    any of them
}