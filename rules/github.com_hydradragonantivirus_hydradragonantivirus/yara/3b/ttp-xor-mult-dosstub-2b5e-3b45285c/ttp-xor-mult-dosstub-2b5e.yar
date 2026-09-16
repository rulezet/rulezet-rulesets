rule TTP_XOR_MULT_DOSStub_2b5e {
  strings:
    $key_2b5e = { 7f 36 [2] 0b 2e [2] 4c 2c [2] 0b 3d [2] 45 31 [2] 49 3b [2] 5e 30 [2] 45 7e [2] 78 }

  condition:
    any of them
}