rule TTP_XOR_MULT_DOSStub_febf {
  strings:
    $key_febf = { aa d7 [2] de cf [2] 99 cd [2] de dc [2] 90 d0 [2] 9c da [2] 8b d1 [2] 90 9f [2] ad }

  condition:
    any of them
}