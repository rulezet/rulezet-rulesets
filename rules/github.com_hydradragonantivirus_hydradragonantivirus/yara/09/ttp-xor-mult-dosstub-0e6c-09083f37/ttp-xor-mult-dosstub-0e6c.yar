rule TTP_XOR_MULT_DOSStub_0e6c {
  strings:
    $key_0e6c = { 5a 04 [2] 2e 1c [2] 69 1e [2] 2e 0f [2] 60 03 [2] 6c 09 [2] 7b 02 [2] 60 4c [2] 5d }

  condition:
    any of them
}