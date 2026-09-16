rule TTP_XOR_MULT_DOSStub_79ed {
  strings:
    $key_79ed = { 2d 85 [2] 59 9d [2] 1e 9f [2] 59 8e [2] 17 82 [2] 1b 88 [2] 0c 83 [2] 17 cd [2] 2a }

  condition:
    any of them
}