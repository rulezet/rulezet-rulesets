rule TTP_XOR_QUAD_CurrentVersionRun_1cda {
  strings:
    $key_1cda = { 4f b5 [2] 6b bb [2] 40 97 [2] 6e b5 [2] 7a ae [2] 75 b4 [2] 6b a9 [2] 69 a8 [2] 72 ae [2] 6e a9 [2] 72 86 }

  condition:
    any of them
}