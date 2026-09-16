rule TTP_XOR_QUAD_CurrentVersionRun_5cda {
  strings:
    $key_5cda = { 0f b5 [2] 2b bb [2] 00 97 [2] 2e b5 [2] 3a ae [2] 35 b4 [2] 2b a9 [2] 29 a8 [2] 32 ae [2] 2e a9 [2] 32 86 }

  condition:
    any of them
}