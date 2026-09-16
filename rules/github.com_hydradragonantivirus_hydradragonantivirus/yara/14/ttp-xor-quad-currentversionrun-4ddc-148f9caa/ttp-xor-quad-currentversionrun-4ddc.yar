rule TTP_XOR_QUAD_CurrentVersionRun_4ddc {
  strings:
    $key_4ddc = { 1e b3 [2] 3a bd [2] 11 91 [2] 3f b3 [2] 2b a8 [2] 24 b2 [2] 3a af [2] 38 ae [2] 23 a8 [2] 3f af [2] 23 80 }

  condition:
    any of them
}