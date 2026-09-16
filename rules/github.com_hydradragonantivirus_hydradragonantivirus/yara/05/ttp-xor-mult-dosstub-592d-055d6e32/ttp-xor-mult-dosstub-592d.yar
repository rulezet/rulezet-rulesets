rule TTP_XOR_MULT_DOSStub_592d {
  strings:
    $key_592d = { 0d 45 [2] 79 5d [2] 3e 5f [2] 79 4e [2] 37 42 [2] 3b 48 [2] 2c 43 [2] 37 0d [2] 0a }

  condition:
    any of them
}