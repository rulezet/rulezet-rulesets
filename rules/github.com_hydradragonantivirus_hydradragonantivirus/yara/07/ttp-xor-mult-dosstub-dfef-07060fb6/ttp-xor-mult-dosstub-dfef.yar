rule TTP_XOR_MULT_DOSStub_dfef {
  strings:
    $key_dfef = { 8b 87 [2] ff 9f [2] b8 9d [2] ff 8c [2] b1 80 [2] bd 8a [2] aa 81 [2] b1 cf [2] 8c }

  condition:
    any of them
}