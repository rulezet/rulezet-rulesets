rule TTP_XOR_QUAD_CurrentVersionRun_c5dc {
  strings:
    $key_c5dc = { 96 b3 [2] b2 bd [2] 99 91 [2] b7 b3 [2] a3 a8 [2] ac b2 [2] b2 af [2] b0 ae [2] ab a8 [2] b7 af [2] ab 80 }

  condition:
    any of them
}