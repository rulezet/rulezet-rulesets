rule TTP_XOR_MULT_DOSStub_6bae {
  strings:
    $key_6bae = { 3f c6 [2] 4b de [2] 0c dc [2] 4b cd [2] 05 c1 [2] 09 cb [2] 1e c0 [2] 05 8e [2] 38 }

  condition:
    any of them
}