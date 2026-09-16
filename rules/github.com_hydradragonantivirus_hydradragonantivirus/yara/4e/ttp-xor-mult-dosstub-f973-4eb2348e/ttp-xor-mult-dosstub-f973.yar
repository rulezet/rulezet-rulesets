rule TTP_XOR_MULT_DOSStub_f973 {
  strings:
    $key_f973 = { ad 1b [2] d9 03 [2] 9e 01 [2] d9 10 [2] 97 1c [2] 9b 16 [2] 8c 1d [2] 97 53 [2] aa }

  condition:
    any of them
}