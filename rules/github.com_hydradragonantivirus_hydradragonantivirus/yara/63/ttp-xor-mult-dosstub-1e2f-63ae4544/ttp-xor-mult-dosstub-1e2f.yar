rule TTP_XOR_MULT_DOSStub_1e2f {
  strings:
    $key_1e2f = { 4a 47 [2] 3e 5f [2] 79 5d [2] 3e 4c [2] 70 40 [2] 7c 4a [2] 6b 41 [2] 70 0f [2] 4d }

  condition:
    any of them
}