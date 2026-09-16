rule TTP_XOR_QUAD_CurrentVersionRun_4fdc {
  strings:
    $key_4fdc = { 1c b3 [2] 38 bd [2] 13 91 [2] 3d b3 [2] 29 a8 [2] 26 b2 [2] 38 af [2] 3a ae [2] 21 a8 [2] 3d af [2] 21 80 }

  condition:
    any of them
}