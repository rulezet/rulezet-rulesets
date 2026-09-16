rule TTP_XOR_MULT_DOSStub_1e0f {
  strings:
    $key_1e0f = { 4a 67 [2] 3e 7f [2] 79 7d [2] 3e 6c [2] 70 60 [2] 7c 6a [2] 6b 61 [2] 70 2f [2] 4d }

  condition:
    any of them
}