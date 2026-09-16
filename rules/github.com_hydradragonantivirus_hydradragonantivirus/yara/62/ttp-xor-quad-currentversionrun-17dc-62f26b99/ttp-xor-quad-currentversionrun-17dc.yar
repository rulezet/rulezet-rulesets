rule TTP_XOR_QUAD_CurrentVersionRun_17dc {
  strings:
    $key_17dc = { 44 b3 [2] 60 bd [2] 4b 91 [2] 65 b3 [2] 71 a8 [2] 7e b2 [2] 60 af [2] 62 ae [2] 79 a8 [2] 65 af [2] 79 80 }

  condition:
    any of them
}