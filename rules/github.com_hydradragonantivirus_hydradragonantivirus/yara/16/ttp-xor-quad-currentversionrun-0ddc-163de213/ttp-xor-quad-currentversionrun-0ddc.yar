rule TTP_XOR_QUAD_CurrentVersionRun_0ddc {
  strings:
    $key_0ddc = { 5e b3 [2] 7a bd [2] 51 91 [2] 7f b3 [2] 6b a8 [2] 64 b2 [2] 7a af [2] 78 ae [2] 63 a8 [2] 7f af [2] 63 80 }

  condition:
    any of them
}