rule TTP_XOR_MULT_DOSStub_2b2f {
  strings:
    $key_2b2f = { 7f 47 [2] 0b 5f [2] 4c 5d [2] 0b 4c [2] 45 40 [2] 49 4a [2] 5e 41 [2] 45 0f [2] 78 }

  condition:
    any of them
}