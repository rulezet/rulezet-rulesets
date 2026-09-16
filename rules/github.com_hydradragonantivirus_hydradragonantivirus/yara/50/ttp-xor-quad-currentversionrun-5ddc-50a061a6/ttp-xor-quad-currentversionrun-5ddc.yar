rule TTP_XOR_QUAD_CurrentVersionRun_5ddc {
  strings:
    $key_5ddc = { 0e b3 [2] 2a bd [2] 01 91 [2] 2f b3 [2] 3b a8 [2] 34 b2 [2] 2a af [2] 28 ae [2] 33 a8 [2] 2f af [2] 33 80 }

  condition:
    any of them
}