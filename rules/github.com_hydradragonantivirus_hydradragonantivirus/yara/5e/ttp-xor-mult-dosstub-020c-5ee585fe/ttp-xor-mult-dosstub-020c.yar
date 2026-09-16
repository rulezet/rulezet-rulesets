rule TTP_XOR_MULT_DOSStub_020c {
  strings:
    $key_020c = { 56 64 [2] 22 7c [2] 65 7e [2] 22 6f [2] 6c 63 [2] 60 69 [2] 77 62 [2] 6c 2c [2] 51 }

  condition:
    any of them
}