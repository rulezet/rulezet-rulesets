rule TTP_XOR_MULT_DOSStub_690e {
  strings:
    $key_690e = { 3d 66 [2] 49 7e [2] 0e 7c [2] 49 6d [2] 07 61 [2] 0b 6b [2] 1c 60 [2] 07 2e [2] 3a }

  condition:
    any of them
}