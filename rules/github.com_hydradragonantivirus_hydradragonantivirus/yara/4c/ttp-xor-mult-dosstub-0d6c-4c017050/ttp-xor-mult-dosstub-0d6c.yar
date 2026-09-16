rule TTP_XOR_MULT_DOSStub_0d6c {
  strings:
    $key_0d6c = { 59 04 [2] 2d 1c [2] 6a 1e [2] 2d 0f [2] 63 03 [2] 6f 09 [2] 78 02 [2] 63 4c [2] 5e }

  condition:
    any of them
}