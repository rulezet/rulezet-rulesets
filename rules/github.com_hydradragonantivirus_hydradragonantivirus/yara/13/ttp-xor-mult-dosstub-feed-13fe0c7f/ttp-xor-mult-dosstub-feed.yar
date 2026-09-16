rule TTP_XOR_MULT_DOSStub_feed {
  strings:
    $key_feed = { aa 85 [2] de 9d [2] 99 9f [2] de 8e [2] 90 82 [2] 9c 88 [2] 8b 83 [2] 90 cd [2] ad }

  condition:
    any of them
}