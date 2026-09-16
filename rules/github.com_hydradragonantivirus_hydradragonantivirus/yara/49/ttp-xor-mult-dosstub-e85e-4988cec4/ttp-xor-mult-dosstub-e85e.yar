rule TTP_XOR_MULT_DOSStub_e85e {
  strings:
    $key_e85e = { bc 36 [2] c8 2e [2] 8f 2c [2] c8 3d [2] 86 31 [2] 8a 3b [2] 9d 30 [2] 86 7e [2] bb }

  condition:
    any of them
}