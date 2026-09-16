rule TTP_XOR_MULT_DOSStub_ec6c {
  strings:
    $key_ec6c = { b8 04 [2] cc 1c [2] 8b 1e [2] cc 0f [2] 82 03 [2] 8e 09 [2] 99 02 [2] 82 4c [2] bf }

  condition:
    any of them
}