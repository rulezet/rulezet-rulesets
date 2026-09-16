rule TTP_XOR_MULT_DOSStub_6aae {
  strings:
    $key_6aae = { 3e c6 [2] 4a de [2] 0d dc [2] 4a cd [2] 04 c1 [2] 08 cb [2] 1f c0 [2] 04 8e [2] 39 }

  condition:
    any of them
}