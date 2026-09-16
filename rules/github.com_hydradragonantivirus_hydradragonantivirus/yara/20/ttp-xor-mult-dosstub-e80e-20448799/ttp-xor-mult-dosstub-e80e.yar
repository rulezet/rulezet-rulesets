rule TTP_XOR_MULT_DOSStub_e80e {
  strings:
    $key_e80e = { bc 66 [2] c8 7e [2] 8f 7c [2] c8 6d [2] 86 61 [2] 8a 6b [2] 9d 60 [2] 86 2e [2] bb }

  condition:
    any of them
}