rule TTP_XOR_QUAD_CurrentVersionRun_9bda {
  strings:
    $key_9bda = { c8 b5 [2] ec bb [2] c7 97 [2] e9 b5 [2] fd ae [2] f2 b4 [2] ec a9 [2] ee a8 [2] f5 ae [2] e9 a9 [2] f5 86 }

  condition:
    any of them
}