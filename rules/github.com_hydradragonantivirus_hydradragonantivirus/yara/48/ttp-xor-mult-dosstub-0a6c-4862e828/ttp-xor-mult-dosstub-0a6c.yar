rule TTP_XOR_MULT_DOSStub_0a6c {
  strings:
    $key_0a6c = { 5e 04 [2] 2a 1c [2] 6d 1e [2] 2a 0f [2] 64 03 [2] 68 09 [2] 7f 02 [2] 64 4c [2] 59 }

  condition:
    any of them
}