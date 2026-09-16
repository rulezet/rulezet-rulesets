rule TTP_XOR_MULT_DOSStub_6f6c {
  strings:
    $key_6f6c = { 3b 04 [2] 4f 1c [2] 08 1e [2] 4f 0f [2] 01 03 [2] 0d 09 [2] 1a 02 [2] 01 4c [2] 3c }

  condition:
    any of them
}