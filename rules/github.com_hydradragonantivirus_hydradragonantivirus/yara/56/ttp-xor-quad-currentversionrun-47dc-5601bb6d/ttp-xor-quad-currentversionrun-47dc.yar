rule TTP_XOR_QUAD_CurrentVersionRun_47dc {
  strings:
    $key_47dc = { 14 b3 [2] 30 bd [2] 1b 91 [2] 35 b3 [2] 21 a8 [2] 2e b2 [2] 30 af [2] 32 ae [2] 29 a8 [2] 35 af [2] 29 80 }

  condition:
    any of them
}