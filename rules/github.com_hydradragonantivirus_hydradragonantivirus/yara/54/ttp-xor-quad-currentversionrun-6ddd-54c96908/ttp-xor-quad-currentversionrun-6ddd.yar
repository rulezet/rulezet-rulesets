rule TTP_XOR_QUAD_CurrentVersionRun_6ddd {
  strings:
    $key_6ddd = { 3e b2 [2] 1a bc [2] 31 90 [2] 1f b2 [2] 0b a9 [2] 04 b3 [2] 1a ae [2] 18 af [2] 03 a9 [2] 1f ae [2] 03 81 }

  condition:
    any of them
}