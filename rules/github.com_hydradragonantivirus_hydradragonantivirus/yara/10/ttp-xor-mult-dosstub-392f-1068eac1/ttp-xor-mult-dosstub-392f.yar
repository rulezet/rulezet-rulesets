rule TTP_XOR_MULT_DOSStub_392f {
  strings:
    $key_392f = { 6d 47 [2] 19 5f [2] 5e 5d [2] 19 4c [2] 57 40 [2] 5b 4a [2] 4c 41 [2] 57 0f [2] 6a }

  condition:
    any of them
}