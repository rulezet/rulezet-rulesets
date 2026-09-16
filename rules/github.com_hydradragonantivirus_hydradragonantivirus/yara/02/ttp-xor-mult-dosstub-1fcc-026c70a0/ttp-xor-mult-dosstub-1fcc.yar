rule TTP_XOR_MULT_DOSStub_1fcc {
  strings:
    $key_1fcc = { 4b a4 [2] 3f bc [2] 78 be [2] 3f af [2] 71 a3 [2] 7d a9 [2] 6a a2 [2] 71 ec [2] 4c }

  condition:
    any of them
}