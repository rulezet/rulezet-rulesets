rule TTP_XOR_QUAD_CurrentVersionRun_1fdc {
  strings:
    $key_1fdc = { 4c b3 [2] 68 bd [2] 43 91 [2] 6d b3 [2] 79 a8 [2] 76 b2 [2] 68 af [2] 6a ae [2] 71 a8 [2] 6d af [2] 71 80 }

  condition:
    any of them
}