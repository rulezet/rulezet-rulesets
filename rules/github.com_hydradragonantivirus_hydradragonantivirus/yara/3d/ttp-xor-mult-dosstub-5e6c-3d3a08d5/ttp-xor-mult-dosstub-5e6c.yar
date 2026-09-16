rule TTP_XOR_MULT_DOSStub_5e6c {
  strings:
    $key_5e6c = { 0a 04 [2] 7e 1c [2] 39 1e [2] 7e 0f [2] 30 03 [2] 3c 09 [2] 2b 02 [2] 30 4c [2] 0d }

  condition:
    any of them
}