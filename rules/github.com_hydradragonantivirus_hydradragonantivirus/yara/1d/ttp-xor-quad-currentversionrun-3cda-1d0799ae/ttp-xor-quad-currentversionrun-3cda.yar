rule TTP_XOR_QUAD_CurrentVersionRun_3cda {
  strings:
    $key_3cda = { 6f b5 [2] 4b bb [2] 60 97 [2] 4e b5 [2] 5a ae [2] 55 b4 [2] 4b a9 [2] 49 a8 [2] 52 ae [2] 4e a9 [2] 52 86 }

  condition:
    any of them
}