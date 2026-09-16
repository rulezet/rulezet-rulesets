rule TTP_XOR_MULT_DOSStub_592e {
  strings:
    $key_592e = { 0d 46 [2] 79 5e [2] 3e 5c [2] 79 4d [2] 37 41 [2] 3b 4b [2] 2c 40 [2] 37 0e [2] 0a }

  condition:
    any of them
}