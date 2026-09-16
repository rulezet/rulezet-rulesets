rule TTP_XOR_MULT_DOSStub_3c2f {
  strings:
    $key_3c2f = { 68 47 [2] 1c 5f [2] 5b 5d [2] 1c 4c [2] 52 40 [2] 5e 4a [2] 49 41 [2] 52 0f [2] 6f }

  condition:
    any of them
}