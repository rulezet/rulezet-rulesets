rule TTP_XOR_MULT_DOSStub_3e2f {
  strings:
    $key_3e2f = { 6a 47 [2] 1e 5f [2] 59 5d [2] 1e 4c [2] 50 40 [2] 5c 4a [2] 4b 41 [2] 50 0f [2] 6d }

  condition:
    any of them
}