rule TTP_XOR_MULT_DOSStub_656c {
  strings:
    $key_656c = { 31 04 [2] 45 1c [2] 02 1e [2] 45 0f [2] 0b 03 [2] 07 09 [2] 10 02 [2] 0b 4c [2] 36 }

  condition:
    any of them
}