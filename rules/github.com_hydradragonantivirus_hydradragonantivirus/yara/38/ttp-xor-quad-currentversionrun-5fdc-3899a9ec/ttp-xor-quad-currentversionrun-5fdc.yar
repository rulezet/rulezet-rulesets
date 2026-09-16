rule TTP_XOR_QUAD_CurrentVersionRun_5fdc {
  strings:
    $key_5fdc = { 0c b3 [2] 28 bd [2] 03 91 [2] 2d b3 [2] 39 a8 [2] 36 b2 [2] 28 af [2] 2a ae [2] 31 a8 [2] 2d af [2] 31 80 }

  condition:
    any of them
}