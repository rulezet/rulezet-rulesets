rule TTP_XOR_QUAD_CurrentVersionRun_43dc {
  strings:
    $key_43dc = { 10 b3 [2] 34 bd [2] 1f 91 [2] 31 b3 [2] 25 a8 [2] 2a b2 [2] 34 af [2] 36 ae [2] 2d a8 [2] 31 af [2] 2d 80 }

  condition:
    any of them
}