rule TTP_XOR_MULT_DOSStub_590f {
  strings:
    $key_590f = { 0d 67 [2] 79 7f [2] 3e 7d [2] 79 6c [2] 37 60 [2] 3b 6a [2] 2c 61 [2] 37 2f [2] 0a }

  condition:
    any of them
}