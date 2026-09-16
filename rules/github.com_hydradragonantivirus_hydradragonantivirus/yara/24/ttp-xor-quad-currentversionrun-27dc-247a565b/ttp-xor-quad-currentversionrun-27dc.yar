rule TTP_XOR_QUAD_CurrentVersionRun_27dc {
  strings:
    $key_27dc = { 74 b3 [2] 50 bd [2] 7b 91 [2] 55 b3 [2] 41 a8 [2] 4e b2 [2] 50 af [2] 52 ae [2] 49 a8 [2] 55 af [2] 49 80 }

  condition:
    any of them
}