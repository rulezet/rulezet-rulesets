rule TTP_XOR_MULT_DOSStub_fcef {
  strings:
    $key_fcef = { a8 87 [2] dc 9f [2] 9b 9d [2] dc 8c [2] 92 80 [2] 9e 8a [2] 89 81 [2] 92 cf [2] af }

  condition:
    any of them
}