rule TTP_XOR_MULT_DOSStub_eced {
  strings:
    $key_eced = { b8 85 [2] cc 9d [2] 8b 9f [2] cc 8e [2] 82 82 [2] 8e 88 [2] 99 83 [2] 82 cd [2] bf }

  condition:
    any of them
}