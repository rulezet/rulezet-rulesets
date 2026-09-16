rule TTP_XOR_QUAD_CurrentVersionRun_ccda {
  strings:
    $key_ccda = { 9f b5 [2] bb bb [2] 90 97 [2] be b5 [2] aa ae [2] a5 b4 [2] bb a9 [2] b9 a8 [2] a2 ae [2] be a9 [2] a2 86 }

  condition:
    any of them
}