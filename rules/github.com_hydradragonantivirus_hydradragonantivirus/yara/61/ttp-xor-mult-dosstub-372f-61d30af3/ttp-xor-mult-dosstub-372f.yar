rule TTP_XOR_MULT_DOSStub_372f {
  strings:
    $key_372f = { 63 47 [2] 17 5f [2] 50 5d [2] 17 4c [2] 59 40 [2] 55 4a [2] 42 41 [2] 59 0f [2] 64 }

  condition:
    any of them
}