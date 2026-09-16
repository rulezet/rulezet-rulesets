rule TTP_XOR_MULT_DOSStub_2bef {
  strings:
    $key_2bef = { 7f 87 [2] 0b 9f [2] 4c 9d [2] 0b 8c [2] 45 80 [2] 49 8a [2] 5e 81 [2] 45 cf [2] 78 }

  condition:
    any of them
}