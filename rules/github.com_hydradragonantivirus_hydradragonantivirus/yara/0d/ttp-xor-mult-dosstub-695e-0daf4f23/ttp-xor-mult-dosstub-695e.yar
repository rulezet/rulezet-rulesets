rule TTP_XOR_MULT_DOSStub_695e {
  strings:
    $key_695e = { 3d 36 [2] 49 2e [2] 0e 2c [2] 49 3d [2] 07 31 [2] 0b 3b [2] 1c 30 [2] 07 7e [2] 3a }

  condition:
    any of them
}