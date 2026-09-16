rule TTP_XOR_MULT_DOSStub_3fbf {
  strings:
    $key_3fbf = { 6b d7 [2] 1f cf [2] 58 cd [2] 1f dc [2] 51 d0 [2] 5d da [2] 4a d1 [2] 51 9f [2] 6c }

  condition:
    any of them
}