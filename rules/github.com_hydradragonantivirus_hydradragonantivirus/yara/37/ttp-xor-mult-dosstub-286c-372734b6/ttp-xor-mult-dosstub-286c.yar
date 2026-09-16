rule TTP_XOR_MULT_DOSStub_286c {
  strings:
    $key_286c = { 7c 04 [2] 08 1c [2] 4f 1e [2] 08 0f [2] 46 03 [2] 4a 09 [2] 5d 02 [2] 46 4c [2] 7b }

  condition:
    any of them
}