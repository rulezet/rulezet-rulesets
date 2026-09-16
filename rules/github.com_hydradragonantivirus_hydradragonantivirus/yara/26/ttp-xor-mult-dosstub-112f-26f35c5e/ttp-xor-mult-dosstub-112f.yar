rule TTP_XOR_MULT_DOSStub_112f {
  strings:
    $key_112f = { 45 47 [2] 31 5f [2] 76 5d [2] 31 4c [2] 7f 40 [2] 73 4a [2] 64 41 [2] 7f 0f [2] 42 }

  condition:
    any of them
}