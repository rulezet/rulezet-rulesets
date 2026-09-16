rule TTP_XOR_MULT_DOSStub_af8e {
  strings:
    $key_af8e = { fb e6 [2] 8f fe [2] c8 fc [2] 8f ed [2] c1 e1 [2] cd eb [2] da e0 [2] c1 ae [2] fc }

  condition:
    any of them
}