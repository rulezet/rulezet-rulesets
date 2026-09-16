rule TTP_XOR_MULT_DOSStub_2cea {
  strings:
    $key_2cea = { 78 82 [2] 0c 9a [2] 4b 98 [2] 0c 89 [2] 42 85 [2] 4e 8f [2] 59 84 [2] 42 ca [2] 7f }

  condition:
    any of them
}