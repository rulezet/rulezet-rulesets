rule TTP_XOR_MULT_DOSStub_116c {
  strings:
    $key_116c = { 45 04 [2] 31 1c [2] 76 1e [2] 31 0f [2] 7f 03 [2] 73 09 [2] 64 02 [2] 7f 4c [2] 42 }

  condition:
    any of them
}