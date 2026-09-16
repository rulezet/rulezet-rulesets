rule TTP_XOR_QUAD_CurrentVersionRun_acda {
  strings:
    $key_acda = { ff b5 [2] db bb [2] f0 97 [2] de b5 [2] ca ae [2] c5 b4 [2] db a9 [2] d9 a8 [2] c2 ae [2] de a9 [2] c2 86 }

  condition:
    any of them
}