rule TTP_XOR_MULT_DOSStub_196c {
  strings:
    $key_196c = { 4d 04 [2] 39 1c [2] 7e 1e [2] 39 0f [2] 77 03 [2] 7b 09 [2] 6c 02 [2] 77 4c [2] 4a }

  condition:
    any of them
}