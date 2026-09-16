rule TTP_XOR_MULT_DOSStub_ba9f {
  strings:
    $key_ba9f = { ee f7 [2] 9a ef [2] dd ed [2] 9a fc [2] d4 f0 [2] d8 fa [2] cf f1 [2] d4 bf [2] e9 }

  condition:
    any of them
}