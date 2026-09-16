rule TTP_XOR_MULT_DOSStub_060f {
  strings:
    $key_060f = { 52 67 [2] 26 7f [2] 61 7d [2] 26 6c [2] 68 60 [2] 64 6a [2] 73 61 [2] 68 2f [2] 55 }

  condition:
    any of them
}