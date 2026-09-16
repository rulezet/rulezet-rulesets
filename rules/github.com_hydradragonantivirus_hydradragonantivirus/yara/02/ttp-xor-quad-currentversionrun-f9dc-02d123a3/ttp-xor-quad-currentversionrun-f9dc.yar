rule TTP_XOR_QUAD_CurrentVersionRun_f9dc {
  strings:
    $key_f9dc = { aa b3 [2] 8e bd [2] a5 91 [2] 8b b3 [2] 9f a8 [2] 90 b2 [2] 8e af [2] 8c ae [2] 97 a8 [2] 8b af [2] 97 80 }

  condition:
    any of them
}