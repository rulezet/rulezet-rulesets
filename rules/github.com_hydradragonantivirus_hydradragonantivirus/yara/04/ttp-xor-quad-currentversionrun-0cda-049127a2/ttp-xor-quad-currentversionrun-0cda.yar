rule TTP_XOR_QUAD_CurrentVersionRun_0cda {
  strings:
    $key_0cda = { 5f b5 [2] 7b bb [2] 50 97 [2] 7e b5 [2] 6a ae [2] 65 b4 [2] 7b a9 [2] 79 a8 [2] 62 ae [2] 7e a9 [2] 62 86 }

  condition:
    any of them
}