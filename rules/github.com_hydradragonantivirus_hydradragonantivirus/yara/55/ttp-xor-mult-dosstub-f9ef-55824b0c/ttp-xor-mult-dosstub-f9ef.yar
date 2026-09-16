rule TTP_XOR_MULT_DOSStub_f9ef {
  strings:
    $key_f9ef = { ad 87 [2] d9 9f [2] 9e 9d [2] d9 8c [2] 97 80 [2] 9b 8a [2] 8c 81 [2] 97 cf [2] aa }

  condition:
    any of them
}