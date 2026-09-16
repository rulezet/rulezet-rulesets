rule TTP_XOR_MULT_DOSStub_256c {
  strings:
    $key_256c = { 71 04 [2] 05 1c [2] 42 1e [2] 05 0f [2] 4b 03 [2] 47 09 [2] 50 02 [2] 4b 4c [2] 76 }

  condition:
    any of them
}