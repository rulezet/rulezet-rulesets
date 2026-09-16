rule TTP_XOR_QUAD_CurrentVersionRun_fcdc {
  strings:
    $key_fcdc = { af b3 [2] 8b bd [2] a0 91 [2] 8e b3 [2] 9a a8 [2] 95 b2 [2] 8b af [2] 89 ae [2] 92 a8 [2] 8e af [2] 92 80 }

  condition:
    any of them
}