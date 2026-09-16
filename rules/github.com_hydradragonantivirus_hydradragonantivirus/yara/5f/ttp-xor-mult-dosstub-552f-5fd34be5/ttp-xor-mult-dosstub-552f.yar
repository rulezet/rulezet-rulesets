rule TTP_XOR_MULT_DOSStub_552f {
  strings:
    $key_552f = { 01 47 [2] 75 5f [2] 32 5d [2] 75 4c [2] 3b 40 [2] 37 4a [2] 20 41 [2] 3b 0f [2] 06 }

  condition:
    any of them
}