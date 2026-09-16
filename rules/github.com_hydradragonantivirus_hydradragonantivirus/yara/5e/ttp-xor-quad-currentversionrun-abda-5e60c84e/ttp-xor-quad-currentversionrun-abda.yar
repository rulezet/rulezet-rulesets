rule TTP_XOR_QUAD_CurrentVersionRun_abda {
  strings:
    $key_abda = { f8 b5 [2] dc bb [2] f7 97 [2] d9 b5 [2] cd ae [2] c2 b4 [2] dc a9 [2] de a8 [2] c5 ae [2] d9 a9 [2] c5 86 }

  condition:
    any of them
}