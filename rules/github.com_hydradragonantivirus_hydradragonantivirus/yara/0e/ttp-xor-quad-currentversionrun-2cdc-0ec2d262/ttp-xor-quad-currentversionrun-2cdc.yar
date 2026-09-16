rule TTP_XOR_QUAD_CurrentVersionRun_2cdc {
  strings:
    $key_2cdc = { 7f b3 [2] 5b bd [2] 70 91 [2] 5e b3 [2] 4a a8 [2] 45 b2 [2] 5b af [2] 59 ae [2] 42 a8 [2] 5e af [2] 42 80 }

  condition:
    any of them
}