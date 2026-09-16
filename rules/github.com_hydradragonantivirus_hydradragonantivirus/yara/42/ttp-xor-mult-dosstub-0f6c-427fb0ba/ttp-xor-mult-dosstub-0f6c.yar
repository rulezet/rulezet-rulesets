rule TTP_XOR_MULT_DOSStub_0f6c {
  strings:
    $key_0f6c = { 5b 04 [2] 2f 1c [2] 68 1e [2] 2f 0f [2] 61 03 [2] 6d 09 [2] 7a 02 [2] 61 4c [2] 5c }

  condition:
    any of them
}