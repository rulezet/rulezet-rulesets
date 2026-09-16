rule TTP_XOR_MULT_DOSStub_496d {
  strings:
    $key_496d = { 1d 05 [2] 69 1d [2] 2e 1f [2] 69 0e [2] 27 02 [2] 2b 08 [2] 3c 03 [2] 27 4d [2] 1a }

  condition:
    any of them
}