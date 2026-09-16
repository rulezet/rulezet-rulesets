rule TTP_XOR_QUAD_CurrentVersionRun_4cda {
  strings:
    $key_4cda = { 1f b5 [2] 3b bb [2] 10 97 [2] 3e b5 [2] 2a ae [2] 25 b4 [2] 3b a9 [2] 39 a8 [2] 22 ae [2] 3e a9 [2] 22 86 }

  condition:
    any of them
}