rule TTP_XOR_QUAD_CurrentVersionRun_1cdc {
  strings:
    $key_1cdc = { 4f b3 [2] 6b bd [2] 40 91 [2] 6e b3 [2] 7a a8 [2] 75 b2 [2] 6b af [2] 69 ae [2] 72 a8 [2] 6e af [2] 72 80 }

  condition:
    any of them
}