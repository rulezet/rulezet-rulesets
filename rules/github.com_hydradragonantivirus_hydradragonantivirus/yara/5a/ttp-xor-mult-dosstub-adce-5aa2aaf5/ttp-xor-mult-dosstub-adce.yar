rule TTP_XOR_MULT_DOSStub_adce {
  strings:
    $key_adce = { f9 a6 [2] 8d be [2] ca bc [2] 8d ad [2] c3 a1 [2] cf ab [2] d8 a0 [2] c3 ee [2] fe }

  condition:
    any of them
}