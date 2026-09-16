rule TTP_XOR_MULT_DOSStub_3e0f {
  strings:
    $key_3e0f = { 6a 67 [2] 1e 7f [2] 59 7d [2] 1e 6c [2] 50 60 [2] 5c 6a [2] 4b 61 [2] 50 2f [2] 6d }

  condition:
    any of them
}