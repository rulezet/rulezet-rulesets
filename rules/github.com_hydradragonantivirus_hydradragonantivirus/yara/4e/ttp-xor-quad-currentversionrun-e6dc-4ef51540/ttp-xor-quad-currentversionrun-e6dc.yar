rule TTP_XOR_QUAD_CurrentVersionRun_e6dc {
  strings:
    $key_e6dc = { b5 b3 [2] 91 bd [2] ba 91 [2] 94 b3 [2] 80 a8 [2] 8f b2 [2] 91 af [2] 93 ae [2] 88 a8 [2] 94 af [2] 88 80 }

  condition:
    any of them
}