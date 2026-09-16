rule TTP_XOR_MULT_DOSStub_2b6c {
  strings:
    $key_2b6c = { 7f 04 [2] 0b 1c [2] 4c 1e [2] 0b 0f [2] 45 03 [2] 49 09 [2] 5e 02 [2] 45 4c [2] 78 }

  condition:
    any of them
}