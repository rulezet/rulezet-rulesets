rule TTP_XOR_MULT_DOSStub_ec23 {
  strings:
    $key_ec23 = { b8 4b [2] cc 53 [2] 8b 51 [2] cc 40 [2] 82 4c [2] 8e 46 [2] 99 4d [2] 82 03 [2] bf }

  condition:
    any of them
}