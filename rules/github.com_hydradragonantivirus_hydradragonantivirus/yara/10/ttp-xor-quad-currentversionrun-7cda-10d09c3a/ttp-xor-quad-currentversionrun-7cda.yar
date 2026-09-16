rule TTP_XOR_QUAD_CurrentVersionRun_7cda {
  strings:
    $key_7cda = { 2f b5 [2] 0b bb [2] 20 97 [2] 0e b5 [2] 1a ae [2] 15 b4 [2] 0b a9 [2] 09 a8 [2] 12 ae [2] 0e a9 [2] 12 86 }

  condition:
    any of them
}