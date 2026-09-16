rule TTP_XOR_QUAD_CurrentVersionRun_1ddc {
  strings:
    $key_1ddc = { 4e b3 [2] 6a bd [2] 41 91 [2] 6f b3 [2] 7b a8 [2] 74 b2 [2] 6a af [2] 68 ae [2] 73 a8 [2] 6f af [2] 73 80 }

  condition:
    any of them
}