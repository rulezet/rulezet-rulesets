rule TTP_XOR_QUAD_CurrentVersionRun_2ddc {
  strings:
    $key_2ddc = { 7e b3 [2] 5a bd [2] 71 91 [2] 5f b3 [2] 4b a8 [2] 44 b2 [2] 5a af [2] 58 ae [2] 43 a8 [2] 5f af [2] 43 80 }

  condition:
    any of them
}