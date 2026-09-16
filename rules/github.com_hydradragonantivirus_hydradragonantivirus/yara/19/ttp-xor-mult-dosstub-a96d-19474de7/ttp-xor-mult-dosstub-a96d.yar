rule TTP_XOR_MULT_DOSStub_a96d {
  strings:
    $key_a96d = { fd 05 [2] 89 1d [2] ce 1f [2] 89 0e [2] c7 02 [2] cb 08 [2] dc 03 [2] c7 4d [2] fa }

  condition:
    any of them
}