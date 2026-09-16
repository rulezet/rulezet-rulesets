rule TTP_XOR_MULT_DOSStub_9e94 {
  strings:
    $key_9e94 = { ca fc [2] be e4 [2] f9 e6 [2] be f7 [2] f0 fb [2] fc f1 [2] eb fa [2] f0 b4 [2] cd }

  condition:
    any of them
}