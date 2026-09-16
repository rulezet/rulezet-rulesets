rule TTP_XOR_QUAD_CurrentVersionRun_f3dc {
  strings:
    $key_f3dc = { a0 b3 [2] 84 bd [2] af 91 [2] 81 b3 [2] 95 a8 [2] 9a b2 [2] 84 af [2] 86 ae [2] 9d a8 [2] 81 af [2] 9d 80 }

  condition:
    any of them
}