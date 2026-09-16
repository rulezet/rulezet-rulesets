rule TTP_XOR_QUAD_CurrentVersionRun_2fdc {
  strings:
    $key_2fdc = { 7c b3 [2] 58 bd [2] 73 91 [2] 5d b3 [2] 49 a8 [2] 46 b2 [2] 58 af [2] 5a ae [2] 41 a8 [2] 5d af [2] 41 80 }

  condition:
    any of them
}