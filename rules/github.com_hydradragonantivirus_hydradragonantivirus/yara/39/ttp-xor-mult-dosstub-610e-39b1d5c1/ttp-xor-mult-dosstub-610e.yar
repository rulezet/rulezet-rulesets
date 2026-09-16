rule TTP_XOR_MULT_DOSStub_610e {
  strings:
    $key_610e = { 35 66 [2] 41 7e [2] 06 7c [2] 41 6d [2] 0f 61 [2] 03 6b [2] 14 60 [2] 0f 2e [2] 32 }

  condition:
    any of them
}