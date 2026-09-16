rule TTP_XOR_MULT_DOSStub_062f {
  strings:
    $key_062f = { 52 47 [2] 26 5f [2] 61 5d [2] 26 4c [2] 68 40 [2] 64 4a [2] 73 41 [2] 68 0f [2] 55 }

  condition:
    any of them
}