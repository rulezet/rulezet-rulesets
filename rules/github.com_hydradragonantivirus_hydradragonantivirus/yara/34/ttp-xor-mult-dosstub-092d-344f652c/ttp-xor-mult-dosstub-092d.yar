rule TTP_XOR_MULT_DOSStub_092d {
  strings:
    $key_092d = { 5d 45 [2] 29 5d [2] 6e 5f [2] 29 4e [2] 67 42 [2] 6b 48 [2] 7c 43 [2] 67 0d [2] 5a }

  condition:
    any of them
}