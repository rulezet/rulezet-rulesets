rule TTP_XOR_QUAD_CurrentVersionRun_fddc {
  strings:
    $key_fddc = { ae b3 [2] 8a bd [2] a1 91 [2] 8f b3 [2] 9b a8 [2] 94 b2 [2] 8a af [2] 88 ae [2] 93 a8 [2] 8f af [2] 93 80 }

  condition:
    any of them
}