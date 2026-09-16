rule TTP_XOR_MULT_DOSStub_2b3e {
  strings:
    $key_2b3e = { 7f 56 [2] 0b 4e [2] 4c 4c [2] 0b 5d [2] 45 51 [2] 49 5b [2] 5e 50 [2] 45 1e [2] 78 }

  condition:
    any of them
}