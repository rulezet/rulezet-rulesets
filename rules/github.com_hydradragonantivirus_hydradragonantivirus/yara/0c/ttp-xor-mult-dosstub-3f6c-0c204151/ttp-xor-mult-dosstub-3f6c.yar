rule TTP_XOR_MULT_DOSStub_3f6c {
  strings:
    $key_3f6c = { 6b 04 [2] 1f 1c [2] 58 1e [2] 1f 0f [2] 51 03 [2] 5d 09 [2] 4a 02 [2] 51 4c [2] 6c }

  condition:
    any of them
}