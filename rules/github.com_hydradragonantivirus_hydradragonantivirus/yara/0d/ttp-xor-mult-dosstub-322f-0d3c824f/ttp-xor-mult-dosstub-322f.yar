rule TTP_XOR_MULT_DOSStub_322f {
  strings:
    $key_322f = { 66 47 [2] 12 5f [2] 55 5d [2] 12 4c [2] 5c 40 [2] 50 4a [2] 47 41 [2] 5c 0f [2] 61 }

  condition:
    any of them
}