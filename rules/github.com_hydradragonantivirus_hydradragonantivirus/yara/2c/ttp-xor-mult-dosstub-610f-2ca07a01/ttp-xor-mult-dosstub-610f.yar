rule TTP_XOR_MULT_DOSStub_610f {
  strings:
    $key_610f = { 35 67 [2] 41 7f [2] 06 7d [2] 41 6c [2] 0f 60 [2] 03 6a [2] 14 61 [2] 0f 2f [2] 32 }

  condition:
    any of them
}