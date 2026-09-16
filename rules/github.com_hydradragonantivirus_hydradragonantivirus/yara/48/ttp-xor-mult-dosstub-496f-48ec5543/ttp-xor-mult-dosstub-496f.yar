rule TTP_XOR_MULT_DOSStub_496f {
  strings:
    $key_496f = { 1d 07 [2] 69 1f [2] 2e 1d [2] 69 0c [2] 27 00 [2] 2b 0a [2] 3c 01 [2] 27 4f [2] 1a }

  condition:
    any of them
}