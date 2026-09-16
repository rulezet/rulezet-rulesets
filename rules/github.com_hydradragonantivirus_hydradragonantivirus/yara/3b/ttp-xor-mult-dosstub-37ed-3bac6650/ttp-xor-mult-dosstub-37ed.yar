rule TTP_XOR_MULT_DOSStub_37ed {
  strings:
    $key_37ed = { 63 85 [2] 17 9d [2] 50 9f [2] 17 8e [2] 59 82 [2] 55 88 [2] 42 83 [2] 59 cd [2] 64 }

  condition:
    any of them
}