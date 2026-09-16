rule TTP_XOR_QUAD_CurrentVersionRun_16dc {
  strings:
    $key_16dc = { 45 b3 [2] 61 bd [2] 4a 91 [2] 64 b3 [2] 70 a8 [2] 7f b2 [2] 61 af [2] 63 ae [2] 78 a8 [2] 64 af [2] 78 80 }

  condition:
    any of them
}